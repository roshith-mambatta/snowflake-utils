import snowflake.connector
import boto3
from botocore.exceptions import ClientError
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import pandas as pd


class SnowflakeConnector:

    def __init__(self, env_secret_key, db_schema):
        self._env_secret_key = env_secret_key
        self._secrets_json = self.get_secret_credentials()
        self._connection_parameters = {
            "user": self._secrets_json['user'],
            "account": self._secrets_json['account'],
            "role": self._secrets_json['role'],
            "private_key": self.get_private_key(),
            "warehouse": self._secrets_json['warehouse'],
            "database": self._secrets_json['database'],
            "schema": db_schema,
            "autocommit": False
        }
        try:
            self._conn = snowflake.connector.connect(**self._connection_parameters)
            self._cursor = self._conn.cursor()
        except Exception as e:
            raise RuntimeError("SnowflakeConnection", f'Error connecting to Snowflake: {e}')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_secret_credentials(self):
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name='us-east-1')
        try:
            secret_response = client.get_secret_value(SecretId=self._env_secret_key)
            secret = json.loads(secret_response['SecretString'])
            return secret
        except ClientError as e:
            raise Exception(f'boto3 client error in get_secret_value: {e}')
        except Exception as e:
            raise Exception(f'Unexpected error in get_secret_value: {e}')

    def get_private_key(self):
        pass_phrase = Fernet(self._secrets_json['pass_phrase_key'])\
            .decrypt(self._secrets_json['pass_phrase_encrypt_text'].encode())\
            .decode()
        p_key = serialization.load_pem_private_key(
            self._secrets_json['rsa_key_p8'],
            password=pass_phrase.encode(),
            backend=default_backend()
        )
        bp_key = p_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        return bp_key

    @property
    def connection(self):
        return self._conn

    @property
    def cursor(self):
        return self._cursor

    def commit(self):
        self.connection.commit()

    def close(self, commit=True):
        if commit:
            self.commit()
        self.cursor.close()
        self.connection.close()

    def fetchall(self):
        return self.cursor.fetchall()

    def fetchone(self):
        return self.cursor.fetchone()

    def rows(self):
        return self.cursor.rowcount()

    def fetch_df_from_sql(self, sql, params=None):
        try:
            query_result = self.cursor.execute(sql, params or ())
            df = pd.DataFrame.from_records(iter(query_result), columns=[row[0] for row in query_result.description])
            return df
        except Exception as e:
            raise RuntimeError(f'SQL statement: {sql}\n threw error: {e}')

    def run_query(self, sql, params=None):
        try:
            self.cursor.execute(sql, params or ())
        except Exception as e:
            raise RuntimeError(f'SQL statement: {sql}\n threw error: {e}')
