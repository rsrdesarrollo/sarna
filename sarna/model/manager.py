from flask_migrate import MigrateCommand
from flask_script import Manager

from sarna.model import *

if __name__ == '__main__':
    manager = Manager(db.app)
    manager.add_command('db', MigrateCommand)
    manager.run()
