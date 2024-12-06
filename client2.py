import pandas as pd

# Data extracted into a structured format
data = {
    "Nodes": [16, 16, 16, 16, 16, 16, 14, 14, 14, 14, 14, 14, 12, 12, 12, 12, 12, 12, 
              10, 10, 10, 10, 10, 10, 8, 8, 8, 8, 8, 8, 6, 6, 6, 6, 6, 6, 4, 4, 4, 4, 4, 4],
    "Characters": [5, 10, 20, 40, 60, 80] * 7,
    "Decryption Time (ms)": [
        24.246459, 24.408666, 24.361375, 24.274, 24.30975, 24.278,
        24.009, 24.1155, 23.883583, 24.554542, 23.999541, 24.100917,
        24.040292, 24.130708, 24.1895, 23.873791, 24.205125, 23.949334,
        24.057458, 23.991917, 24.160083, 24.134667, 24.072, 23.836417,
        24.120542, 24.093667, 24.030042, 23.97675, 24.0325, 24.057041,
        24.286208, 24.40775, 24.26875, 24.368125, 24.37825, 24.366458,
        24.278833, 24.18125, 24.266042, 39.651, 24.034833, 24.272708],
    "End-to-End Time": [
        "2024-12-04 17:16:19.125843", "2024-12-04 17:17:12.890645", "2024-12-04 17:17:45.113075", 
        "2024-12-04 17:18:19.523941", "2024-12-04 17:18:48.856616", "2024-12-04 17:19:28.394867",
        "2024-12-04 17:22:53.670451", "2024-12-04 17:24:27.419119", "2024-12-04 17:24:51.417248",
        "2024-12-04 17:25:48.826524", "2024-12-04 17:26:11.386183", "2024-12-04 17:26:42.494896",
        "2024-12-04 17:29:36.932104", "2024-12-04 17:30:00.224905", "2024-12-04 17:30:26.314277",
        "2024-12-04 17:30:51.227044", "2024-12-04 17:31:14.707479", "2024-12-04 17:31:40.500688",
        "2024-12-04 17:34:02.128613", "2024-12-04 17:34:26.435961", "2024-12-04 17:34:33.270696",
        "2024-12-04 17:34:39.772885", "2024-12-04 17:34:46.545518", "2024-12-04 17:34:52.606865",
        "2024-12-04 17:36:08.013721", "2024-12-04 17:36:22.661796", "2024-12-04 17:36:29.340139",
        "2024-12-04 17:36:36.635708", "2024-12-04 17:36:43.867727", "2024-12-04 17:36:49.860255",
        "2024-12-04 17:38:53.054518", "2024-12-04 17:39:00.399368", "2024-12-04 17:39:06.477007",
        "2024-12-04 17:39:12.839508", "2024-12-04 17:39:19.160844", "2024-12-04 17:39:26.391703",
        "2024-12-04 17:41:00.862379", "2024-12-04 17:41:07.678266", "2024-12-04 17:41:14.358452",
        "2024-12-04 17:41:21.968096", "2024-12-04 17:41:28.654605", "2024-12-04 17:41:37.927771"
    ]
}

# Creating DataFrame
df = pd.DataFrame(data)

# Save to Excel
file_path = "/mnt/data/Decryption_Times.xlsx"
df.to_excel(file_path, index=False)

file_path