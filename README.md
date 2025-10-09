# simple-redis-iam

fastapi_project/
├── app/
│   ├── __init__.py
│   ├── main.py              # Entry point for FastAPI app
│   ├── api/                 # API route definitions
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── endpoints/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── users.py
│   │   │   │   ├── auth.py
│   │   │   │   └── items.py
│   ├── core/                # Core settings, config, security
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── security.py
│   ├── models/              # SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── item.py
│   ├── schemas/             # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── item.py
│   ├── services/            # Business logic
│   │   ├── __init__.py
│   │   ├── user_service.py
│   │   ├── item_service.py
│   ├── db/                  # Database session and init
│   │   ├── __init__.py
│   │   ├── session.py
│   │   ├── base.py
│   └── utils/               # Utility functions
│       ├── __init__.py
│       ├── helpers.py
│       ├── logger.py
├── tests/                   # Unit and integration tests
│   ├── __init__.py
│   ├── test_users.py
│   ├── test_auth.py
├── requirements.txt         # Python dependencies
├── .env                     # Environment variables
├── alembic/                 # DB migrations (if using Alembic)
│   ├── versions/
│   ├── env.py
│   └── README
└── README.md                # Project documentation


TODO:

1. redis configuration + hardening
2. JWT approach?
3. improve structure
4. forntend - IAM identification?