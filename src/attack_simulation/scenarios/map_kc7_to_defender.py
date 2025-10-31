import os
import pandas as pd 
import argparse
import shutil
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.data_generation.defender_xdr.base import Base
from src.attack_simulation.scenarios.utils.DataMapper import DataMapper

def configure_database(database_uri):  
    engine = create_engine(database_uri, echo=False)
    Session = sessionmaker(bind=engine)
    session = Session()

    try:  
        # Drop and recreate tables if needed  
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        print("✅ Tables created successfully!")
    except Exception as e:  
        print(f"❌ Error creating tables: {e}")
  
    return engine, session  

def orchestrator(mapper, path, file):
    df = pd.read_csv(os.path.join(path, file))
    if file == "Employees.csv":
        mapper.map_identity_info(df)
        mapper.map_devices(df)
    elif file == "Email.csv":
        mapper.map_emails(df)
    elif file == "AuthenticationEvents.csv":
        mapper.map_authentication_events(df)
    elif file == "FileCreationEvents.csv":
        mapper.map_file_events(df)
    elif file == "ProcessEvents.csv":
        mapper.map_process_events(df)
    elif file == "InboundNetworkEvents.csv":
        mapper.map_network_events(df, "in")
    elif file == "OutboundNetworkEvents.csv":
        mapper.map_network_events(df, "out")
    elif file == "NetworkFlow.csv":
        mapper.map_network_flow(df)
    elif file == "SecurityAlerts.csv":
        mapper.map_alerts(df)
    elif file == "PassiveDns.csv":
        mapper.map_passive_dns(df)
    else:
        print(f"Unknown file: {file}")

def create_translated_environment(session, engine, scenario):
    
    mapper = DataMapper(session)
    db_path = f"src/attack_simulation/scenarios/agentdefender/csv_database/{scenario}/"
    for file_name in os.listdir(db_path):
        if file_name.lower().endswith(".csv"):
            orchestrator(mapper, db_path, file_name)

def prepare_directories(scenario, output_base_dir):
    # Ensures the base directory exists, then delete the scenario directory
    # first if it already exists, then re-creates it

    scenario_dir = os.path.join(output_base_dir, scenario)
    if not os.path.exists(output_base_dir):
        try:
            os.mkdir(output_base_dir)
            print("Created base directory %s", output_base_dir)
        except Exception as e:
            print("Error creating base directory %s: %s", output_base_dir, e)
            return

    if os.path.exists(scenario_dir):
        try:
            shutil.rmtree(scenario_dir)
            print("Removed existing scenario directory %s", scenario_dir)
        except Exception as e:
            print("Error removing existing directory %s: %s", scenario_dir, e)
            return
    try:
        os.makedirs(scenario_dir, exist_ok=True)
        print("Created scenario directory %s", scenario_dir)
    except Exception as e:
        print("Error creating scenario directory %s: %s", scenario_dir, e)
        return

def export_tables_to_csv(engine, scenario, output_base_dir = 'output_scenarios'):
    """Export each table from Base.metadata to a CSV file prefixed with the scenario name."""

    prepare_directories(scenario, output_base_dir)

    for table_name in Base.metadata.tables.keys():
        csv_filename = f"output_scenarios/{scenario}/{table_name}.csv"
        try:
            # This uses read_sql_table if supported; otherwise fall back to a generic query.
            df = pd.read_sql_table(table_name, con=engine)
        except Exception:
            query = f"SELECT * FROM {table_name}"
            df = pd.read_sql(query, con=engine)
        try:
            df.to_csv(csv_filename, index=False)
            print(f"Exported {table_name} to {csv_filename}")
        except Exception as e:
            print(f"Error writing {csv_filename}: {e}")

def map_scenario(scenario):
    DATABASE_URI = 'mysql+pymysql://datagen:graphgen@localhost:3306/alphahunt'
    engine, session = configure_database(DATABASE_URI)
    create_translated_environment(session, engine, scenario)
    export_tables_to_csv(engine, scenario)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument( "--scenario", type=str, help="Path to the input file.", default="SolviSystems") 
    args = parser.parse_args()
    scenario = args.scenario

    kc7_scenarios = [
        "AzureCrest", "CJWalker", "DominationNation", "GlobalGoodwill", "KrustyKrab", 
        "Scholomance", "TitanShield", "BalloonsOverIowa", "CastleSand", 
        "EncryptoDera", "HopsNStuff", "NorthPoleWorkshop", "SolviSystems", "ValdyTimes", 
        "woodgrove-loganalyiticsworkspace", "BancoMares", "ChicagoPower", 
        "EnvolveLabs_Analysis", "JadePalace", "OwlRecords", "SpookySweets", "ValdyX2", 
        "BeatsStudio", "DaiWokFoods", "Envolvelabs_ThreatIntel", "JoJosHospital", 
        "SASA", "Sunlands"
    ]

    scenarios = kc7_scenarios if scenario == 'all' else [scenario]

    for scenario in scenarios:
        map_scenario(scenario)

    print("Data generation complete. The database is populated with the attack scenario data.")
  
if __name__ == "__main__":  
    main()