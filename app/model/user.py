from flask_login import UserMixin

# User class
class User(UserMixin):
    def __init__(self, id):
        self.id = id