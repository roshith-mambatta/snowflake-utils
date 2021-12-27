from utils.snowflake_connect import SnowflakeConnector

with SnowflakeConnector(env_secret_key='dev/snowflake', db_schema='dev_schema') as sf:
    sf.run_query("SELECT current_version()")
    sf.run_query("COPY INTO ...")
    sf.fetchone()
    df = sf.fetch_df_from_sql("select * from table")
    print(df)
    sf.commit()

