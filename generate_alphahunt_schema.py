import os
import sys
import ast
import json
import argparse

# Usage
# python generate_alphahunt_schema.py -i /path/to/tables/ -d MyDatabaseName -o schema.json

# Mapping from SQLAlchemy type name to (full system type, Kusto CSL type)
TYPE_MAPPING = {
    "String": ("System.String", "string"),
    "LONGTEXT": ("System.String", "string"),
    "Text": ("System.String", "string"),
    "DateTime": ("System.DateTime", "datetime"),
    "Integer": ("System.Int32", "int"),
    "BigInteger": ("System.Int32", "int"),
    "Boolean": ("System.Boolean", "bool"),
    "Float": ("System.Double", "real"),
}

def get_string_value(node):
    """Extracts a string value from an ast.Constant (Python 3.8+) or ast.Str node."""
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Str):
        return node.s
    return None

def parse_table_class(class_node):
    """
    Given an ast.ClassDef node, check if it defines a tablename attribute and
    if so, return a tuple (table_name, ordered_columns) where ordered_columns is a list
    of column dictionaries.
    """
    table_name = None
    ordered_columns = []


    # First, look for __tablename__  
    for stmt in class_node.body:  
        if isinstance(stmt, ast.Assign):  
            # Look for a target named __tablename__  
            for target in stmt.targets:  
                if isinstance(target, ast.Name) and target.id == "__tablename__":  
                    val = get_string_value(stmt.value)  
                    if val:  
                        table_name = val  
                    break  
            if table_name:  
                break  

    # If no table name found, this class is not a table definition.  
    if not table_name:  
        return None, None  

    # Iterate again over class body to find columns  
    # We assume each column is defined with a simple assignment like:  
    #   ColumnName = Column(<type>, ... )  
    for stmt in class_node.body:  
        if isinstance(stmt, ast.Assign):  
            # Skip __tablename__ assignment (and any private attributes)  
            if (len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)  
                and stmt.targets[0].id.startswith("__")):  
                continue  

            # Get the attribute name  
            if not (len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):  
                continue  
            col_name = stmt.targets[0].id  

            # We expect the value to be a call like Column(...)  
            if not isinstance(stmt.value, ast.Call):  
                continue  

            call_node = stmt.value  
            # Check that the call is to a function named "Column"  
            if isinstance(call_node.func, ast.Name) and call_node.func.id == "Column":  
                # Make sure there is at least one positional argument (the type)  
                if not call_node.args:  
                    print(f"Warning: Column '{col_name}' in table '{table_name}' has no type specified.")  
                    continue  
                type_candidate = call_node.args[0]  
                # The type may be a call (e.g., String(255)) or a Name (e.g., DateTime)  
                type_name = None  
                if isinstance(type_candidate, ast.Call):  
                    if isinstance(type_candidate.func, ast.Name):  
                        type_name = type_candidate.func.id  
                elif isinstance(type_candidate, ast.Name):  
                    type_name = type_candidate.id  
                else:  
                    # For more complex expressions, you might try ast.unparse(type_candidate)  
                    # but here we just skip.  
                    print(f"Warning: Could not determine type for column '{col_name}' in table '{table_name}'.")  
                    continue  

                if type_name not in TYPE_MAPPING:  
                    print(f"Warning: Type '{type_name}' of column '{col_name}' in table '{table_name}' is not recognized. Skipping column.")  
                    continue  

                full_type, csl_type = TYPE_MAPPING[type_name]  
                ordered_columns.append({  
                    "Name": col_name,  
                    "Type": full_type,  
                    "CslType": csl_type  
                })  
            else:  
                # Not a Column(...) call; skip.  
                continue  

    if not ordered_columns:  
        print(f"Warning: Table '{table_name}' did not yield any column definitions.")  
    return table_name, ordered_columns
 
def parse_python_file(file_path):
    """
    Parse a single Python file and return a dictionary mapping table names to
    their table definition (with Name and OrderedColumns).
    """
    tables = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            file_contents = f.read()
            tree = ast.parse(file_contents, filename=file_path)
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return tables

    for node in ast.iter_child_nodes(tree):  
        if isinstance(node, ast.ClassDef):  
            table_name, columns = parse_table_class(node)  
            if table_name and columns:  
                # In case of duplicate table names, later file wins  
                tables[table_name] = {  
                    "Name": table_name,  
                    "OrderedColumns": columns  
                }  
    return tables
    
def generate_schema(input_dir, database_name):
    """
    Walks through the input directory and aggregates all table definitions
    into a schema structure (a dict) following the format:
    {  
    "<database_name>": {  
        "Name": "<database_name>",  
        "Tables": {  
            "<table_name>": { "Name": "<table_name>",  
                                "OrderedColumns": [ ... ] },  
            ...  
        }  
    }  
    }  
    """  
    all_tables = {}  
    if not os.path.isdir(input_dir):  
        print(f"Error: {input_dir} is not a valid directory.")  
        sys.exit(1)  

    for file in os.listdir(input_dir):  
        if file.endswith(".py"):  
            file_path = os.path.join(input_dir, file)  
            file_tables = parse_python_file(file_path)  
            if file_tables:  
                # Merge table definitions; if there are duplicate table names, the last one will override.  
                all_tables.update(file_tables)  
                print(f"Processed {file}: found {len(file_tables)} table(s).")  
            else:  
                print(f"Processed {file}: no table definitions found.")  

    schema = {  
        database_name: {  
            "Name": database_name,  
            "Tables": all_tables  
        }  
    }  
    return schema

def main():
    parser = argparse.ArgumentParser(description="Generate a schema.json file from SQLAlchemy table definition files.")
    parser.add_argument("-i", "--input", required=True,
    help="Input directory containing table .py files")
    parser.add_argument("-d", "--database", required=True,
    help="Database name to use in the generated schema")
    parser.add_argument("-o", "--output", default="schema.json",
    help="Output schema JSON file (default: schema.json)")
    args = parser.parse_args()

    schema = generate_schema(args.input, args.database)  

    try:  
        with open(args.output, "w", encoding="utf-8") as out_file:  
            json.dump(schema, out_file, indent=2)  
        print(f"Schema successfully written to '{args.output}'.")  
    except Exception as e:  
        print(f"Error writing schema to file '{args.output}': {e}")  
        sys.exit(1)  
 
if __name__ == "__main__":
    main()
