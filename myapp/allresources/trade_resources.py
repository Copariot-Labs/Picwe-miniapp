
from myapp.app import  status_of_pro
import okx.MarketData as MarketData
import okx.Trade as Trade


flag = "0" if status_of_pro == 0 else "1"  # live trading: 0, demo trading: 1

# 如果 status_of_pro 为 0，使用 live 的值，否则使用 demo 的值
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
        return {'code': 404, 'message': '未找到价格', 'data': []}, 200
    price = float(result['data'][0]['last'])
    return price

def get_random_prices(symbol):
    price = get_price_from_okx(symbol)
    return price
