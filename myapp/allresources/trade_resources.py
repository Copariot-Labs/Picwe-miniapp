
from myapp.app import  status_of_pro
import okx.MarketData as MarketData
import okx.Trade as Trade


flag = "0" 


api_key = "" if status_of_pro == 0 else ""
secret_key = "" if status_of_pro == 0 else ""
passphrase = ""  

tradeAPI = Trade.TradeAPI(api_key, secret_key, passphrase, False, flag)
marketDataAPI = MarketData.MarketAPI(api_key, secret_key, passphrase, False, flag)

percent_of_fee = 0.01

def get_price_from_okx(symbol):

    result = marketDataAPI.get_ticker(
        instId=symbol + "-USDT"
    )
    if not result:
        return {'code': 404, 'message': '1', 'data': []}, 200
    price = float(result['data'][0]['last'])
    return price

def get_random_prices(symbol):
    price = get_price_from_okx(symbol)
    return price
