from celery import Celery
import os

celery = Celery(__name__)
celery.conf.broker_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
celery.conf.result_backend = os.environ.get("REDIS_URL", "redis://localhost:6379")


def init_celery(app):
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
