import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
from tqdm import tqdm

from ..utils import generate_aad_sign_in_events

class PasswordSprayAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time, num_attempts_per_victim=10):

        self.fake = Faker()
        self.benign_data = benign_data
        self.victims = victims
        self.last_scan_time = last_scan_time
        self.attacker = attacker
        self.num_attempts_per_victim = num_attempts_per_victim
        self.data = None

    def generate_password_spray_attack(self):  
        aad_sign_in_events = []  
        targeted_accounts = []

        campaign_time = self.fake.date_time_between(start_date=self.last_scan_time, end_date=datetime.today())  

        for victim in tqdm(self.victims.iter_rows(named=True), desc="Generating password spray events"):  
            targeted_accounts.append(victim["AccountUpn"])  
            for i in range(self.num_attempts_per_victim):   
                attempt_time = campaign_time + timedelta(seconds=random.randint(0, 30) + i * 30)  
                event = generate_aad_sign_in_events(  
                    identity_row=victim,  
                    timestamp=attempt_time,  
                    fake=self.fake,
                    ip_address=self.attacker["SenderIPv4"], 
                )   
                event["ErrorCode"] = random.choice([50053, 50126, 50140, 50144])  
                aad_sign_in_events.append(event)  

        self.data = {  
            "aad_sign_in_events_beta": pl.DataFrame(aad_sign_in_events).sort("Timestamp")  
        }  
        targeted_accounts = self.victims.filter(pl.col("AccountUpn").is_in(targeted_accounts))
        last_event_time = self.data["aad_sign_in_events_beta"]["Timestamp"].max() if not self.data["aad_sign_in_events_beta"].is_empty() else None

        return self.data, targeted_accounts, last_event_time

    def generate_question_answer_pairs(self):  

        events = self.data["aad_sign_in_events_beta"]  
        benign_events = self.benign_data["aad_sign_in_events_beta"]
        all_sign_in_events = pl.concat([events, benign_events], how="vertical")

        questions = []  
        answers = []  

        # Q1. Total number of sign-in attempts (attack plus benign).  
        questions.append("How many total sign-in attempts were recorded (attack plus benign)?")  
        total_attempts = all_sign_in_events.height  
        answers.append(total_attempts)  

        # Q2. Number of unique accounts targeted (based on AccountUpn).  
        questions.append("How many unique accounts (by AccountUpn) appear in the sign-in events?")  
        if all_sign_in_events.height:  
            unique_accounts = all_sign_in_events.select(pl.col("AccountUpn").n_unique()).item()  
        else:  
            unique_accounts = 0  
        answers.append(unique_accounts)  

        # Q3. Most common error code reported among all sign-in events.  
        questions.append("What is the most common error code returned among all sign-in events?")  
        if all_sign_in_events.height and "ErrorCode" in all_sign_in_events.columns:  
            # Group by ErrorCode and sort by occurrence (descending)  
            error_counts = all_sign_in_events.group_by("ErrorCode").count().sort("count", descending=True)  
            most_common_error = error_counts.row(0)[0] if error_counts.height else "N/A"  
        else:  
            most_common_error = "N/A"  
        answers.append(most_common_error)  

        # Q4. Duration (in seconds) between the earliest and the latest sign-in event.  
        questions.append("What is the duration (in seconds) between the first and last sign-in events?")  
        if all_sign_in_events.height:  
            # Retrieve all Timestamp values from the combined DataFrame.  
            timestamps = all_sign_in_events.get_column("Timestamp").to_list()  
            duration = (max(timestamps) - min(timestamps)).total_seconds()  
        else:  
            duration = "N/A"  
        answers.append(duration)  

        # Q5. Number of users that had 10 or more failed sign-in attempts in the last day.
        questions.append("How many users had 10 or more failed sign-in attempts in the last day?")
        if all_sign_in_events.height:
            recent_failed_attempts = all_sign_in_events.filter(
                (pl.col("Timestamp") >= (datetime.now() - timedelta(days=1))) & 
                (pl.col("ErrorCode").is_not_null())
            )
            user_failed_attempts = recent_failed_attempts.group_by("AccountUpn").agg(pl.count()).filter(pl.col("count") >= 10)
            Q5_answer = user_failed_attempts.height
        else:
            Q5_answer = 0
        answers.append(Q5_answer)



        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)  

