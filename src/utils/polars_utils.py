import polars as pl

def safe_concat(frames: list[pl.DataFrame]) -> pl.DataFrame:
    """
    Vertically concatenate DataFrames, ignoring empty ones and
    conforming their schemas to the first non-empty frame.
    """
    frames = [f for f in frames if f.shape[1] and f.shape[0]]   # non-empty only
    if not frames:
        return pl.DataFrame()

    ref_cols = frames[0].columns
    aligned  = []
    for df in frames:
        # add missing columns as nulls
        miss = [c for c in ref_cols if c not in df.columns]
        if miss:
            df = df.with_columns([pl.lit(None).alias(c) for c in miss])
        # drop extras
        extra = set(df.columns) - set(ref_cols)
        if extra:
            df = df.drop(*extra)
        # reorder
        aligned.append(df.select(ref_cols))

    return pl.concat(aligned, how="vertical_relaxed")
