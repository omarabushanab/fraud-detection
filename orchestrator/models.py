from sqlalchemy import create_engine, Column, String, DateTime, LargeBinary, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class UserAccount(Base):
    __tablename__ = 'user_accounts'
    # Unique identifier (e.g., the user's Gmail address)
    email = Column(String, primary_key=True)
    # The pickled credentials object (encrypted in a real production environment)
    credentials = Column(LargeBinary, nullable=False)
    # The last historyId we processed for this specific user
    last_history_id = Column(String, nullable=True)

# Setup database connection
engine = create_engine('sqlite:///users.db')
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)