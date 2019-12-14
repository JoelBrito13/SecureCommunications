import json


class User:
    def __init__(self, user_name, file="resources/users.json"):
        self.file = file
        self.key = ''
        with open(file, 'r') as users_file:
            self.data = json.load(users_file)
            for key in self.data.keys():
                if self.data[key]["user_name"] == user_name:
                    self.key = key
                    self.user = self.data[key]

    def update(self):
        self.data[self.key] = self.user
        with open(self.file, 'w') as file:
            json.dump(self.data, file)

    def add_disk(self, amount=1):
        self.user["data_used"] += amount
        if self.user["role"] == "ADMIN":
            return True
        if self.user["data_used"] > self.user["data_total"]:
            return False
        return True

    def remove_disk(self, amount):
        self.user["data_used"] -= amount

    def is_valid(self):
        return self.key != ''
