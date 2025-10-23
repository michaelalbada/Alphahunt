import polars as pl

def build_dataframe_from_schema(model_cls, column_map, n, victims_df=None):
    """
    Build a Polars DataFrame with columns matching the Pydantic model schema.
    - model_cls: The Pydantic model class.
    - column_map: Dict mapping schema field names to generated column lists.
    - n: Number of rows.
    - victims_df: Optional, for fields present in victims_df.
    """
    schema_fields = list(model_cls.model_fields.keys())
    data_dict = {}
    for field in schema_fields:
        if victims_df is not None and field in victims_df.columns:
            data_dict[field] = victims_df[field].to_list()
        elif field in column_map:
            data_dict[field] = column_map[field]
        else:
            data_dict[field] = [None] * n
    return pl.DataFrame(data_dict)

def auto_column_map(schema_fields, local_vars, manual_overrides=None):
    """
    Automatically map schema fields to local variables named <field>_col.
    manual_overrides: dict of {field: value} for special cases.
    """
    manual_overrides = manual_overrides or {}
    column_map = {}
    for field in schema_fields:
        if field in manual_overrides:
            column_map[field] = manual_overrides[field]
        else:
            column_map[field] = local_vars.get(f"{field}_col", None)
    return column_map 