import pytest
from app import create_app
from app.extensions import db
from app.models.user import User


@pytest.fixture
def app():
    """Create and configure a clean testing app instance."""
    app = create_app("testing")

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """A test client for making requests."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def auth_client(client, app):
    """A test client with an authenticated user session."""
    with app.app_context():
        user = User(username="test_auditor", email="auditor@autoshield.pk", role="auditor")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        # Login via test client
        with client.session_transaction() as sess:
            sess["_user_id"] = str(user.id)
            sess["_fresh"] = True

    return client
