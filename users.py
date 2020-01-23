import json


class User:
    def __init__(self, user_name, file="resources/users.json"):
        self.file = file
        self.user = ''
        with open(file, 'r') as users_file:
            self.data = json.load(users_file)
            for user in self.data:
                if user["user_name"] == user_name:
                    self.user = user

    def update(self):
        for u in self.data:
            if u == self.user: 
                u = self.user
        with open(self.file, 'w') as file:
            json.dump(self.data, file)
            print("Updated")

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
        return self.user != ''
