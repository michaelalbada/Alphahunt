import os  
import argparse  
import pandas as pd  
from sqlalchemy import create_engine, inspect  
from sqlalchemy.exc import SQLAlchemyError  
  
def parse_arguments():  
    parser = argparse.ArgumentParser(  
        description='Export all tables from a MySQL database to CSV files in a specified folder.'  
    )  
    parser.add_argument(  
        '-f', '--folder',  
        type=str,  
        default='csv_output',  
        help='Name of the parent folder to store CSV files (default: csv_output)'  
    )  
    return parser.parse_args()  
  
def create_parent_folder(folder_name):  
    if not os.path.exists(folder_name):  
        try:  
            os.makedirs(folder_name)  
            print(f'Created directory: {folder_name}')  
        except OSError as e:  
            print(f'Error creating directory "{folder_name}": {e}')  
            exit(1)  
    else:  
        print(f'Directory already exists: {folder_name}')  
  
def connect_to_database():  
    try:  
        engine = create_engine(f'mysql+pymysql://datagen:graphgen@localhost:3306/alphahunt')  
        # Test the connection  
        connection = engine.connect()  
        connection.close()  
        print(f'Successfully connected to the database alphahunt.')  
        return engine  
    except SQLAlchemyError as e:  
        print(f'Error connecting to the database: {e}')  
        exit(1)  
  
def export_tables_to_csv(engine, folder_name):  
    try:  
        inspector = inspect(engine)  
        tables = inspector.get_table_names()  
        if not tables:  
            print('No tables found in the database.')  
            return  
  
        for table in tables:  
            try:  
                print(f'Processing table: {table}')  
                df = pd.read_sql_table(table, engine)  
                  
                # Check if the DataFrame is empty  
                if df.empty:  
                    print(f'  -> Skipping table "{table}" as it contains no data.')  
                    continue  # Skip to the next table  
  
                csv_file = os.path.join(folder_name, f'{table}.csv')  
                df.to_csv(csv_file, index=False)  
                print(f'  -> Exported to {csv_file}')  
            except ValueError as ve:  
                print(f'  -> Skipping table "{table}" (possibly a view or unsupported type). Error: {ve}')  
            except SQLAlchemyError as sqle:  
                print(f'  -> Failed to export table "{table}". SQLAlchemy Error: {sqle}')  
            except Exception as e:  
                print(f'  -> Failed to export table "{table}". Error: {e}')  
    except SQLAlchemyError as e:  
        print(f'Failed to retrieve table names. Error: {e}')  
  
def main():  
    args = parse_arguments()  
    folder_name = args.folder  
  
    create_parent_folder(folder_name)  
  
    engine = connect_to_database()  
    export_tables_to_csv(engine, folder_name)  
  
    engine.dispose()  
  
if __name__ == '__main__':  
    main()  