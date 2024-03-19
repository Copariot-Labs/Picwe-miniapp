from myapp.app import *
from myapp.extensions import *
from myapp.models import *
from myapp.allresources.trade_resources import *
from myapp.bot.bot_resource import *



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
