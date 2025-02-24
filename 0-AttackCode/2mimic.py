import time
from datetime import datetime
from requests import post


def change_state(entity_id, new_state):
    print(entity_id, new_state)
    url = "http://192.168.0.159:8123/api/states/" + entity_id

    state_data = {
        "state": new_state,
    }

    headers = {
        "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjYmY5Njg1MmI1MjQ0NTQzYjZhZjE4YzFhYmNhYzYzZSIsImlhdCI6MTY3Nzg0NTc2NiwiZXhwIjoxOTkzMjA1NzY2fQ.xhxAScjVnMAcrNkob45jYSHg0UqqEta5atn3-7JrnKE",
        "content-type": "application/json",
    }
    print(entity_id, new_state)
    try:
        response = post(url, headers=headers, json=state_data)
    except Exception as e:
        print(response.text)

entity_id = "switch.cuco_v3_f204_switch_2"
new_state = "off"
change_state(entity_id, new_state)