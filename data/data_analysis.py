import numpy as np
import pandas as pd

def import_data(file_path: str) -> pd.DataFrame:
    '''Imports data from a CSV file and returns it as a Pandas DataFrame.'''
    data = pd.read_csv(file_path)
    return data


if __name__ == "__main__":
    df_broadcaster_encrypted = import_data('data\\broadcaster_encrypted.csv')
    df_broadcaster_mixed = import_data('data\\broadcaster_mixed.csv')
    df_receiver_encrypted = import_data('data\\receiver_encrypted.csv')
    df_receiver_mixed = import_data('data\\receiver_mixed.csv')

    print(f"{df_broadcaster_encrypted.head()}\n")
    print(f"{df_broadcaster_mixed.head()}\n")

    print("Encrypted Data:")
    print("Rows:", df_broadcaster_encrypted.shape[0])
    print(f"Percentage of Encrypted rows: {((df_broadcaster_encrypted['status'] == 'ENCRYPTED').sum() / len(df_broadcaster_encrypted)) * 100:.2f}%")

    print("\nAverage encryption time:", df_broadcaster_encrypted['encrypt_or_select_ms'].mean())
    print("Maximum encryption time:", df_broadcaster_encrypted['encrypt_or_select_ms'].max())
    print("Minimum encryption time:", df_broadcaster_encrypted['encrypt_or_select_ms'].min())
    print("Median encryption time:", df_broadcaster_encrypted['encrypt_or_select_ms'].median())

    print("\nAverage packet build time:", df_broadcaster_encrypted['packet_build_ms'].mean())
    print("Maximum packet build time:", df_broadcaster_encrypted['packet_build_ms'].max())
    print("Minimum packet build time:", df_broadcaster_encrypted['packet_build_ms'].min())
    print("Median packet build time:", df_broadcaster_encrypted['packet_build_ms'].median())

    print("\nAverage packet send time:", df_broadcaster_encrypted['send_ms'].mean())
    print("Maximum packet send time:", df_broadcaster_encrypted['send_ms'].max())
    print("Minimum packet send time:", df_broadcaster_encrypted['send_ms'].min())
    print("Median packet send time:", df_broadcaster_encrypted['send_ms'].median())

    print("\nAverage total time:", df_broadcaster_encrypted['total_packet_ms'].mean())
    print("Maximum total time:", df_broadcaster_encrypted['total_packet_ms'].max())
    print("Minimum total time:", df_broadcaster_encrypted['total_packet_ms'].min())
    print("Median total time:", df_broadcaster_encrypted['total_packet_ms'].median())

    print("\nMixed Data:")
    print("Rows:", df_broadcaster_mixed.shape[0])
    print(f"Percentage of Encrypted rows: {((df_broadcaster_mixed['status'] == 'ENCRYPTED').sum() / len(df_broadcaster_mixed)) * 100:.2f}%")
    print(f"Percentage of Unencrypted rows: {((df_broadcaster_mixed['status'] == 'PLAIN').sum() / len(df_broadcaster_mixed)) * 100:.2f}%")
    print("\nAverage encryption time for encrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("ENCRYPTED"), "encrypt_or_select_ms"].mean())
    print("Average packet build time for encrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("ENCRYPTED"), "packet_build_ms"].mean())
    print("Average packet build time for unencrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("PLAIN"), "packet_build_ms"].mean())
    print("Average packet send time for encrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("ENCRYPTED"), "send_ms"].mean())
    print("Average packet send time for unencrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("PLAIN"), "send_ms"].mean())
    print("Average total time for encrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("ENCRYPTED"), "total_packet_ms"].mean())
    print("Average total time for unencrypted rows:", df_broadcaster_mixed.loc[df_broadcaster_mixed["status"].eq("PLAIN"), "total_packet_ms"].mean())
