import random
from datetime import datetime, timedelta
from faker import Faker
from tqdm import tqdm
import polars as pl
import networkx as nx

from src.attack_simulation.components.utils import (
    generate_identity_info,
    generate_aad_sign_in_events,
    generate_device_info,
    generate_device_events,
    generate_device_file_events,
    generate_device_process_events,
    generate_email_events,
    generate_inbound_network_events,
    generate_outbound_network_events
)
from src.utils.logging_utils import BaseLogger
from src.benign_simulation.org_graph import (
    build_company_graph,
    ROLE_VOLUME_MULTIPLIERS,
)
from .artifacts_by_role import ROLE_PROCESSES, ROLE_DIRS, ROLE_EXTS

class BenignActivityGenerator:
    def __init__(self, 
                 num_employees=30, 
                 start_date='2025-06-01', 
                 end_date='2025-06-08',
                 num_sign_ins_per_user_min=1,
                 num_sign_ins_per_user_max=5,
                 num_devices_per_user_min=1,
                 num_devices_per_user_max=3,
                 device_events_per_user_min=1,
                 device_events_per_user_max=5,
                 device_file_events_per_user_min=1,
                 device_file_events_per_user_max=5,
                 device_process_events_min=1,
                 device_process_events_max=5,
                 emails_per_user_min=1,
                 emails_per_user_max=5,
                 network_events_per_user_min=1,
                 network_events_per_user_max=5,
                 logger=None):
        self.G = nx.Graph()
        self.num_employees = num_employees
        self.start_date = datetime.strptime(start_date, '%Y-%m-%d')
        self.end_date = datetime.strptime(end_date, '%Y-%m-%d')
        self.fake = Faker()

        self.num_sign_ins_per_user_min = num_sign_ins_per_user_min
        self.num_sign_ins_per_user_max = num_sign_ins_per_user_max
        self.num_devices_per_user_min = num_devices_per_user_min
        self.num_devices_per_user_max = num_devices_per_user_max
        self.device_events_per_user_min = device_events_per_user_min
        self.device_events_per_user_max = device_events_per_user_max
        self.device_file_events_per_user_min = device_file_events_per_user_min
        self.device_file_events_per_user_max = device_file_events_per_user_max
        self.device_process_events_min = device_process_events_min
        self.device_process_events_max = device_process_events_max
        self.emails_per_user_min = emails_per_user_min
        self.emails_per_user_max = emails_per_user_max
        self.network_events_per_user_min = network_events_per_user_min
        self.network_events_per_user_max = network_events_per_user_max
        self.logger = logger or BaseLogger(logger_name="BenignActivity")
    
    def _create_scale_free_topology(self, m: int = 2):
        """
        Attach a Barabási-Albert (scale-free) edge topology to the existing
        device / server nodes.

        m = number of edges each new node adds.  (m=2 gives a good
            “few hubs, many spokes” distribution.)
        """
        # collect endpoint + server nodes (exclude user nodes)
        endpoints = [n for n,attr in self.G.nodes(data=True)
                    if attr.get("ntype") in {"device", "server"}]

        n = len(endpoints)
        if n < 3:
            return

        m = max(1, min(m, n-1))
        ba = nx.barabasi_albert_graph(n, m)

        for u, v in ba.edges():
            src, dst = endpoints[u], endpoints[v]
            self.G.add_edge(src, dst, etype="network")

    def _assign_devices(self, identity_df: pl.DataFrame, device_df: pl.DataFrame):
        for device_id in device_df["DeviceId"]:
            self.G.add_node(device_id, ntype="device")

        for user_row in identity_df.iter_rows(named=True):
            n_devices = random.randint(self.num_devices_per_user_min,
                                       self.num_devices_per_user_max)
            unclaimed = [
                d for d in device_df["DeviceId"] if self.G.degree(d) == 0
            ]
            for device_id in random.sample(unclaimed, min(n_devices, len(unclaimed))):
                self.G.add_edge(user_row["AccountUpn"], device_id)

    def _sample_timestamp(self, day, work_start=8, work_end=18, p_off_hours=0.15):
        """Return a datetime on 'day' biased toward working hours."""
        if random.random() < p_off_hours: # off hours
            hour  = random.randint(0, 23)
        else: # business hours
            hour  = random.randint(work_start, work_end - 1)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        return datetime(day.year, day.month, day.day, hour, minute, second)

    def generate_data(self):
        data = {}
        identity_info_df = self._build_identity_table()
        data["identity_info"] = identity_info_df
        event_start = self.start_date
        event_end = self.end_date

        data["aad_sign_in_events_beta"] = self.generate_sign_in_events(identity_info_df, event_start, event_end)
        data["device_info"] = self.generate_device_info(identity_info_df)
        self._assign_devices(identity_info_df, data["device_info"])
        self._create_scale_free_topology(m=2)
        data["device_events"] = self.generate_device_events(identity_info_df, data["device_info"], event_start, event_end)
        data["device_file_events"] = self.generate_device_file_events(identity_info_df, data["device_info"], event_start, event_end)
        data["device_process_events"] = self.generate_device_process_events(identity_info_df, data["device_info"], event_start, event_end)
        data["email_events"] = self.generate_email_events(identity_info_df, event_start, event_end)
        data["device_network_events"] = self.generate_network_events(identity_info_df, data["device_info"], event_start, event_end)
        return data  

    def _build_identity_table(self) -> pl.DataFrame:
        """
        • Build OrgGraph → self.G
        • Call legacy generate_identity_info to get all the other columns
        • Overwrite columns so that UPNs = OrgGraph UPNs
        • Append Role / Department / Team / ManagerUpn
        """
        org_graph, people = build_company_graph(self.num_employees)
        self.G = org_graph.to_undirected()

        base_df = generate_identity_info(self.num_employees, self.fake, self.end_date)

        # guarantee same order
        people_sorted = sorted(people, key=lambda p: p.upn)[: len(base_df)]
        base_df = base_df.sort("AccountUpn") # same sort key
        base_df = base_df.with_columns([
            pl.Series("AccountUpn", [p.upn for p in people_sorted]),
            pl.Series("AccountDisplayName", [p.full_name for p in people_sorted]),
            pl.Series("AccountName", [p.upn.split("@")[0] for p in people_sorted]),
            pl.Series("AccountDomain", [p.upn.split("@")[1] for p in people_sorted]),
            pl.Series("Department", [p.department for p in people_sorted]),
            pl.Series("Role", [p.role_class for p in people_sorted]),
            pl.Series("Team", [p.team.split(":")[-1] for p in people_sorted]),
            pl.Series("ManagerUpn", [p.manager_upn or "" for p in people_sorted]),
        ])
        return base_df

    @staticmethod
    def _scale(min_v: int, max_v: int, role: str) -> tuple[int, int]:
        m = ROLE_VOLUME_MULTIPLIERS[role]
        return (max(1, int(min_v * m)), max(1, int(max_v * m)))

    def _choose_sender(self, identity_info_df, recipient_upn: str) -> dict | None:
        """
        80 % sender within ≤2 hops in org graph, else random external.
        Returns identity-row dict or None for external sender.
        """
        # 20 % external
        if random.random() > 0.8:
            return None

        hops = nx.single_source_shortest_path_length(self.G, recipient_upn, 2)
        internal_choices = [
            n for n in hops
            if self.G.nodes[n].get("ntype") == "person" and n != recipient_upn
        ]
        if not internal_choices:
            return None
        sender_upn = random.choice(internal_choices)
        return identity_info_df.filter(
            pl.col("AccountUpn") == sender_upn
        ).row(0, named=True)

    def _get_devices_for_user(self, account_upn, device_info_df):
        device_ids = [
            n for n in self.G.neighbors(account_upn) if self.G.nodes[n]["ntype"] == "device"]
        return device_info_df.filter(pl.col("DeviceId").is_in(device_ids))

    def _date_range(self, start_date, end_date):
        current_date = start_date
        while current_date <= end_date:
            yield current_date
            current_date += timedelta(days=1)

    def _pick_process_and_file(self, role: str, account_name: str):
        proc = random.choice(ROLE_PROCESSES.get(role, ROLE_PROCESSES[role]))
        base_dir = random.choice(ROLE_DIRS.get(role, ROLE_DIRS[role]))
        base_dir = base_dir.replace("%USER%", account_name)

        ext   = random.choice(ROLE_EXTS.get(role, ROLE_EXTS[role]))
        fname = f"{self.fake.word()}{ext}"

        full_path = f"{base_dir}\\{fname}" if "\\" in base_dir else f"{base_dir}/{fname}"
        return proc, fname, full_path

    def generate_sign_in_events(self, identity_info_df, start_date, end_date):
        rows = []
        for id_row in tqdm(identity_info_df.iter_rows(named=True),
                           total=len(identity_info_df),
                           desc="Sign-in events"):
            lo, hi = self._scale(self.num_sign_ins_per_user_min,
                                 self.num_sign_ins_per_user_max,
                                 id_row["Role"])
            for day in self._date_range(start_date, end_date):
                timestamps = [self._sample_timestamp(day)
                              for _ in range(random.randint(lo, hi))]
                rows += [generate_aad_sign_in_events(id_row, t, self.fake)
                         for t in timestamps]
        return pl.DataFrame(rows).sort("Timestamp")

    def generate_device_info(self, identity_info_df):
        events = []
        for identity_row in tqdm(identity_info_df.iter_rows(named=True), total=len(identity_info_df), desc="Generating device info"):
            num_devices = random.randint(self.num_devices_per_user_min, self.num_devices_per_user_max)
            for _ in range(num_devices):
                # Using a timestamp from the identity info for device creation
                timestamp = identity_row["Timestamp"]
                event = generate_device_info(identity_row, timestamp, self.fake)
                events.append(event)
        df = pl.DataFrame(events)
        return df.sort("Timestamp")

    def generate_device_events(self, identity_info_df, device_info_df, start_date, end_date):  
        events = []  
        for identity_row in tqdm(identity_info_df.iter_rows(named=True), total=len(identity_info_df), desc="Generating device events"):  
            user_devices = self._get_devices_for_user(identity_row["AccountUpn"], device_info_df)
            for day in self._date_range(start_date, end_date):  
                lo, hi = self._scale(self.device_events_per_user_min, self.device_events_per_user_max, identity_row["Role"])
                num_events = random.randint(lo, hi)
                timestamps = [self._sample_timestamp(day) for _ in range(num_events)]
                for device_row in user_devices.iter_rows(named=True):  
                    events.extend([generate_device_events(identity_row, device_row, timestamp, self.fake) for timestamp in timestamps])
        df = pl.DataFrame(events)
        return df.sort("Timestamp")

    def generate_device_file_events(self, identity_info_df, device_info_df, start_date, end_date):    
        events = []  
        for identity_row in tqdm(identity_info_df.iter_rows(named=True), total=len(identity_info_df), desc="Generating device file events"):  
            user_devices = self._get_devices_for_user(identity_row["AccountUpn"], device_info_df)
            for day in self._date_range(start_date, end_date):  
                lo, hi = self._scale(self.device_file_events_per_user_min, self.device_file_events_per_user_max, identity_row["Role"])
                num_events = random.randint(lo, hi) 
                timestamps = [self._sample_timestamp(day) for _ in range(num_events)]
                for device_row in user_devices.iter_rows(named=True):  
                    _, file_name, file_path = self._pick_process_and_file(identity_row["Role"], identity_row["AccountName"])
                    events.extend([generate_device_file_events(identity_row, device_row, timestamp, self.fake, file_name=file_name,
                        file_path=file_path) for timestamp in timestamps])
        df = pl.DataFrame(events)
        return df.sort("Timestamp")  

    def generate_device_process_events(self, identity_info_df, device_info_df, start_date, end_date):  
        events = []  
        for identity_row in tqdm(identity_info_df.iter_rows(named=True), total=len(identity_info_df), desc="Generating device process events"):  
            user_devices = self._get_devices_for_user(identity_row["AccountUpn"], device_info_df)
            for day in self._date_range(start_date, end_date):  
                lo, hi = self._scale(self.device_process_events_min, self.device_process_events_max, identity_row["Role"])
                num_events = random.randint(lo, hi)
                timestamps = [self._sample_timestamp(day) for _ in range(num_events)]
                for device_row in user_devices.iter_rows(named=True):  
                    proc_name, _, _ = self._pick_process_and_file(identity_row["Role"],
                                              identity_row["AccountName"])
                    cmd_line = f"{proc_name} {self.fake.file_path(depth=1)}"
                    events.extend([generate_device_process_events(identity_row, device_row, timestamp, self.fake, file_name=proc_name,
                        process_command_line=cmd_line) for timestamp in timestamps])  
        df = pl.DataFrame(events)
        return df.sort("Timestamp")

    def generate_email_events(self, identity_info_df, start_date, end_date):
        events = []
        for recip in tqdm(identity_info_df.iter_rows(named=True),
                          total=len(identity_info_df),
                          desc="E-mail events"):
            lo, hi = self._scale(self.emails_per_user_min, self.emails_per_user_max, recip["Role"])
            for day in self._date_range(start_date, end_date):
                k = random.randint(lo, hi)
                timestamps = [self._sample_timestamp(day) for _ in range(k)]
                for ts in timestamps:
                    sender_row = self._choose_sender(identity_info_df, recip["AccountUpn"])
                    in_net = sender_row is not None
                    events.append(
                        generate_email_events(
                            sender_row, recip, ts, in_net, self.fake,
                            know_sender=bool(in_net)
                        )
                    )
        return pl.DataFrame(events).sort("Timestamp")

    def generate_network_events(self,
                            identity_info_df: pl.DataFrame,
                            device_info_df:   pl.DataFrame,
                            start_date: datetime,
                            end_date:   datetime) -> pl.DataFrame:

        events = []
        # pre-index PublicIP by DeviceId for O(1) look-ups
        ip_lookup = dict(zip(device_info_df["DeviceId"], device_info_df["PublicIP"]))

        for id_row in tqdm(identity_info_df.iter_rows(named=True),
                        total=len(identity_info_df),
                        desc="Generating network events"):

            user_devices = self._get_devices_for_user(id_row["AccountUpn"], device_info_df)

            for day in self._date_range(start_date, end_date):

                lo, hi = self._scale(self.network_events_per_user_min,
                                    self.network_events_per_user_max,
                                    id_row["Role"])
                num_events = random.randint(lo, hi)
                timestamps = [self._sample_timestamp(day) for _ in range(num_events)]

                for dev_row in user_devices.iter_rows(named=True):

                    # neighbours that belong to the scale-free backbone
                    neigh = [n for n in self.G.neighbors(dev_row["DeviceId"])
                            if self.G.nodes[n].get("ntype") in {"device", "server"}]

                    for ts in timestamps:
                        # 70 %: real peer
                        if random.random() < 0.7 and neigh:
                            remote_dev  = random.choice(neigh)
                            remote_ip   = ip_lookup.get(remote_dev, self.fake.ipv4())
                        else:
                            remote_dev  = None
                            remote_ip   = self.fake.ipv4()

                        remote_url  = self.fake.url()
                        remote_port = random.randint(1, 65535)
                        inbound     = random.choice([True, False])

                        if inbound:
                            evt = generate_inbound_network_events(
                                    id_row, dev_row, ts, self.fake,
                                    remote_ip, remote_url, remote_port)
                        else:
                            evt = generate_outbound_network_events(
                                    id_row, dev_row, ts, self.fake,
                                    remote_ip, remote_url, remote_port)

                        events.append(evt)

        return pl.DataFrame(events).sort("Timestamp")
