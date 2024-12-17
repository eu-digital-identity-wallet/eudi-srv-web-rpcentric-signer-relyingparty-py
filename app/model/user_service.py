
from model.user import User

# Mock database
users = [
        {
            'username': 'rp',
            'password': 'pass123'
        },
        {
            'username': 'user1',
            'password': 'pass456'
        }
    ]


class UserService:

    # returns the user logged in if successful
    @staticmethod
    def login(username, password):        
        for user in users:
            if user['username'] == username and user['password'] == password: 
                user = User(username)
                return user
        else:
            return None
    
    
    @staticmethod
    def get_users():
        return users