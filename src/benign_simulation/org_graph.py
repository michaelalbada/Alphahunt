"""
org_graph.py
────────────
Creates a realistic, hierarchical organisation graph that can be used as the
single source-of-truth for role, reporting-line and team information.

» Nodes
    • company:<name>           root
    • dept:<name>              departments
    • team:<name>              teams
    • <user_upn>               individual employees

» Directed edges  (all point downwards)
    company → department               etype = "division_of"
    department → team                  etype = "part_of"
    person → manager(person)           etype = "reports_to"
    person  → team                     etype = "member_of"

All attributes live on the nodes, so downstream generators can pull them in O(1).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple
import argparse
import networkx as nx
from faker import Faker

# --------------------------------------------------------------------------- #
#  Configuration                                                              #
# --------------------------------------------------------------------------- #

DEFAULT_DEPARTMENTS = [
    "Engineering", "Sales", "Finance", "Human Resources",
    "Marketing", "IT", "Security", "Customer Success"
]

# probability of each role class
ROLE_CLASS_WEIGHTS = {
    "admin": 0.05,
    "engineer": 0.55,
    "sales": 0.15,
    "corporate": 0.18,
    "intern": 0.07
}

# Multiplicative factors for log volumes, process counts, etc.
ROLE_VOLUME_MULTIPLIERS = {
    "admin": 2.5,
    "engineer": 1.0,
    "sales": 1.3,
    "corporate": 0.8,
    "intern": 0.4
}

SENIORITY_BY_ROLE = {
    "admin":    ["senior", "exec"],
    "engineer": ["junior", "mid", "senior"],
    "sales":    ["junior", "mid", "senior"],
    "corporate": ["junior", "mid", "senior"],
    "intern":   ["junior"]
}

# Fan-out distribution for management hierarchy (min,max) for each layer
FAN_OUT = {
    "exec":   (4, 8),     # CEO → C-suite
    "vp":     (3, 10),    # C-suite → VPs / Directors
    "mgr":    (4, 9)      # Managers → ICs
}

fake = Faker()

# --------------------------------------------------------------------------- #
#  Dataclasses for clarity (only Person is needed for external use)           #
# --------------------------------------------------------------------------- #

@dataclass
class Person:
    upn: str
    full_name: str
    job_title: str
    role_class: str
    seniority: str
    department: str
    team: str
    manager_upn: str | None = None


# --------------------------------------------------------------------------- #
#  Builder Class                                                              #
# --------------------------------------------------------------------------- #

class OrgGraphBuilder:
    """Build an organisational graph with realistic hierarchy and metadata."""

    def __init__(
        self,
        num_employees: int = 250,
        company_name: str | None = None,
        domain: str | None = None,
        departments: List[str] | None = None,
        seed: int | None = None
    ):
        if seed is not None:
            random.seed(seed)

        self.num_employees = max(5, num_employees)
        self.company_name = company_name or fake.company()
        # simple domain heuristics
        self.domain = domain or (
            self.company_name.lower()
            .replace(" ", "")
            .replace(",", "")
            .replace(".", "")
        ) + ".com"

        self.departments = departments or DEFAULT_DEPARTMENTS
        # if fewer depts requested than default set, sample
        max_depts = min(len(self.departments), int(len(self.departments) * 0.6) + 3)
        self.departments = random.sample(self.departments, k=max_depts)

        self.G = nx.DiGraph()
        self.people: Dict[str, Person] = {}  # upn -> Person dataclass

        self._build_company()

    # ─────────────────────────────────────────────────────────────────── #
    #  Public API                                                        #
    # ─────────────────────────────────────────────────────────────────── #

    def graph(self) -> nx.DiGraph:
        """Return the fully populated organisation graph."""
        return self.G

    def persons(self) -> List[Person]:
        return list(self.people.values())

    # ─────────────────────────────────────────────────────────────────── #
    #  Internal helpers                                                  #
    # ─────────────────────────────────────────────────────────────────── #

    def _build_company(self):
        self._add_root_nodes()
        self._add_departments_and_teams()
        self._build_people()
        self._wire_reporting_lines()

    # -- company / dept / team nodes ----------------------------------- #

    def _add_root_nodes(self):
        self.G.add_node(f"company:{self.company_name}",
                        ntype="company",
                        name=self.company_name)

    def _add_departments_and_teams(self):
        for dept in self.departments:
            dept_node = f"dept:{dept}"
            self.G.add_node(dept_node, ntype="department", name=dept)
            self.G.add_edge(f"company:{self.company_name}", dept_node,
                            etype="division_of")

            # Each department has 1-4 teams
            n_teams = random.randint(1, 4)
            for i in range(n_teams):
                team_name = f"{dept}-{i+1}"
                team_node = f"team:{team_name}"
                self.G.add_node(team_node, ntype="team",
                                name=team_name, department=dept)
                self.G.add_edge(dept_node, team_node, etype="part_of")

    # -- people generation --------------------------------------------- #

    def _sample_role_class(self) -> str:
        roles, probs = zip(*ROLE_CLASS_WEIGHTS.items())
        return random.choices(roles, probs)[0]

    def _sample_seniority(self, role_class: str) -> str:
        return random.choice(SENIORITY_BY_ROLE[role_class])

    def _create_person(self, role_class: str, seniority: str,
                       department: str, team: str) -> Person:
        first = fake.first_name()
        last  = fake.last_name()
        upn   = f"{first.lower()}.{last.lower()}@{self.domain}"
        job_title = self._derive_job_title(role_class, seniority)

        return Person(
            upn=upn,
            full_name=f"{first} {last}",
            job_title=job_title,
            role_class=role_class,
            seniority=seniority,
            department=department,
            team=team
        )

    def _derive_job_title(self, role: str, seniority: str) -> str:
        # Very simple mapping; extend as needed
        base = {
            "admin": "System Administrator",
            "engineer": "Software Engineer",
            "sales": "Account Executive",
            "corporate": "Financial Analyst",
            "intern": "Intern"
        }[role]

        prefix = {
            "junior": "Junior",
            "mid": "",
            "senior": "Senior",
            "exec": "Chief",
        }.get(seniority, "")

        return f"{prefix} {base}".strip()

    def _build_people(self):
        """
        Create all employees, attach them to teams.
        Manager hierarchy wired later.
        """
        team_nodes = [n for n, d in self.G.nodes(data=True) if d["ntype"] == "team"]

        for _ in range(self.num_employees):
            team_node = random.choice(team_nodes)
            dept = self.G.nodes[team_node]["department"]

            role_class  = self._sample_role_class()
            seniority   = self._sample_seniority(role_class)

            person = self._create_person(role_class, seniority, dept, team_node)
            self.people[person.upn] = person

            # Add node & team membership edge
            self.G.add_node(person.upn, ntype="person", **asdict(person))
            self.G.add_edge(person.upn, team_node, etype="member_of")


    def _wire_reporting_lines(self):
        """
        Assign a realistic management hierarchy and make sure *every*
        employee except the CEO has a manager.
        """
        ceo = random.choice(list(self.people.values()))
        ceo.role_class, ceo.seniority, ceo.job_title = (
            "admin", "exec", "Chief Executive Officer"
        )
        self.G.nodes[ceo.upn].update(asdict(ceo))

        execs, vps, managers, ics = [], [], [], []
        for p in self.people.values():
            if p.upn == ceo.upn:
                continue
            if p.role_class in ["admin", "corporate"] and p.seniority in ["senior", "exec"]:
                execs.append(p)
            elif p.seniority == "senior":
                vps.append(p)
            elif p.seniority in ["mid", "senior"]:
                managers.append(p)
            else:
                ics.append(p)

        self._fanout_connect(ceo, execs, *FAN_OUT["exec"])
        for exec_ in execs:
            self._fanout_connect(exec_, vps, *FAN_OUT["vp"])
        for vp in vps:
            self._fanout_connect(vp, managers, *FAN_OUT["vp"])
        for mgr in managers:
            self._fanout_connect(mgr, ics, *FAN_OUT["mgr"])

        # Any employee (except CEO) with no manager yet → attach to a random
        # manager who already *has* at least one report; if that list turns
        # out empty, fall back to the CEO.
        orphans = [p for p in self.people.values()
                   if p.manager_upn is None and p.upn != ceo.upn]

        # eligible managers = anyone who already manages, otherwise CEO only
        eligible_mgrs = [p for p in self.people.values()
                         if list(self.G.predecessors(p.upn))]
        if not eligible_mgrs:
            eligible_mgrs = [ceo]

        for orphan in orphans:
            mgr = random.choice(eligible_mgrs)
            self._report(orphan, mgr)

    def _fanout_connect(self,
                        manager: Person,
                        candidates: List[Person],
                        min_reports: int,
                        max_reports: int):
        if not candidates:
            return
        num = random.randint(min_reports, max_reports)
        reports = random.sample(candidates, k=min(num, len(candidates)))
        for report in reports:
            self._report(report, manager)
            # remove from candidate pool so they don't get another manager
            candidates.remove(report)

    def _report(self, report: Person, manager: Person):
        report.manager_upn = manager.upn
        self.G.add_edge(report.upn, manager.upn, etype="reports_to")

def build_company_graph(num_employees: int = 250,
                        seed: int | None = None) -> Tuple[nx.DiGraph, List[Person]]:
    """
    Stateless helper for quick use:

        G, people = build_company_graph(400, seed=42)
    """
    builder = OrgGraphBuilder(num_employees=num_employees, seed=seed)
    return builder.graph(), builder.persons()

def _print_summary(G: nx.DiGraph, people: List[Person]):
    company = next(n for n, d in G.nodes(data=True) if d["ntype"] == "company")
    print(f"\nOrganisation for {G.nodes[company]['name']}")
    print("─────────────────────────────────────────────")
    print(f"Total employees      : {len(people)}")
    print(f"Departments          : {len([n for n,d in G.nodes(data=True) if d['ntype']=='department'])}")
    print(f"Teams                : {len([n for n,d in G.nodes(data=True) if d['ntype']=='team'])}")
    print(f"Managers (≥1 report) : {len([p for p in people if list(G.predecessors(p.upn))])}")

    # sample a few employees
    print("\nSample employees")
    print("----------------")
    for p in random.sample(people, k=min(5, len(people))):
        mgr = p.manager_upn or "—"
        print(f"{p.full_name:<25}  {p.job_title:<30}  Team:{p.team.split(':')[-1]:<16}  Manager:{mgr}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an organisational graph and print a summary.")
    parser.add_argument("--num-employees", "-n", type=int, default=250, help="Total number of employees")
    parser.add_argument("--seed", "-s", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument(
        "--graphml", "-g", type=str, default=None,
        help="Path to save the graph as GraphML (optional)"
    )
    args = parser.parse_args()

    G, people = build_company_graph(num_employees=args.num_employees, seed=args.seed)

    _print_summary(G, people)

    if args.graphml:
        nx.write_graphml(G, args.graphml)
        print(f"\nGraphML written to {args.graphml}")