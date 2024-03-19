
from datetime import datetime
from decimal import Decimal
import hashlib
import hmac
import json
from urllib.parse import parse_qs, unquote

from loguru import logger
import requests
from cryptography.fernet import Fernet
from flask import  request, redirect, render_template
from flask_login import current_user, login_required, login_user, logout_user
from telebot import TeleBot, types
from telebot.types import  InlineKeyboardButton, InlineKeyboardMarkup, LoginUrl, Update

from myapp.allresources.trade_resources import get_random_prices
from myapp.app import app,  db , status_of_pro 
from myapp.models import Asset, AssetType,  Order, PointTransaction, User, UserKey
from myapp.allresources.web3_tool import (approve_point_token_logic, check_tx_status_logic, open_channel_logic, validate_ethereum_address,
                                            get_web3,create_eth_wallet,split_secret,load_abi,get_gas_price,get_nonce,sign_and_send_transaction,
                                            load_key,decrypt_private_key_from_db, withdraw_part_point_logic,
                                            CHAIN_NAME,TX_BASE_URL,TOKEN ,simple_pUSDT_address,pUSDT_address)
import okx.PublicData as PublicData


bot = TeleBot(TOKEN)
bot.remove_webhook()


LOGIN_URL = 'https://app.picwe.org/bot/tg_login' 
BOT_USERNAME = '@picwe_bot' 
PHOTO_PATH = 'logo_mini.jpg'

webhook_url = f'https://app.picwe.org/{TOKEN}' 

bot.set_webhook(url=webhook_url)

############################## function ############################
def get_decimal_value(symbol):
    flag = "0"  

    publicDataAPI = PublicData.PublicAPI(flag=flag)
    result = publicDataAPI.get_instruments(
        instType="SPOT",
        instId=symbol + "-USDT"
    )
    return float(result['data'][0]['minSz'])

def bot_transfer_ether(user_id, to_address, amount, speed, chain):
    try:
        to_address = validate_ethereum_address(to_address)
    except ValueError:
        return {'code': 400, 'message': 'Invalid Ethereum address'}, 400

    # Get user's ethereum address from UserKey model
    user_key = UserKey.query.filter_by(user_id=user_id).first()
    if user_key is None:
        return {'code': 404, 'message': 'UserKey not found', 'data': []}, 200

    # Decrypt private key from db
    address, private_key = decrypt_private_key_from_db(user_id)
    if isinstance(private_key, tuple):  
        return private_key
    
    try:
        w3 = get_web3(chain)
        slow_gas_price, average_gas_price, fast_gas_price = get_gas_price(w3)
        gas_prices = {'slow': slow_gas_price, 'average': average_gas_price, 'fast': fast_gas_price}
    except ValueError:
        return {'code': 400, 'message': '不支持的链', 'data': []}, 200

    nonce = get_nonce(w3, address)

    tx = {
        'nonce': nonce,
        'to': to_address,
        'value': w3.to_wei(amount, 'ether'),
        'gas': 70000,
        'gasPrice': gas_prices[speed],
        'chainId': w3.eth.chain_id
    }

    tx_hash = sign_and_send_transaction(w3, tx, private_key)
    if isinstance(tx_hash, tuple):  
        return tx_hash
    # Delete the private key from memory
    del private_key
    return tx_hash.hex()

def bot_transfer_erc20(user_id, to_address, amount, speed, chain, contract_address):
    try:
        to_address = validate_ethereum_address(to_address)
    except ValueError:
        return {'code': 400, 'message': 'Invalid Ethereum address'}, 400

    # Get user's ethereum address from UserKey model
    user_key = UserKey.query.filter_by(user_id=user_id).first()
    if user_key is None:
        return {'code': 404, 'message': 'UserKey not found', 'data': []}, 200

    # Decrypt private key from db
    address, private_key = decrypt_private_key_from_db(user_id)
    if isinstance(private_key, tuple):  
        return private_key
    
    try:
        w3 = get_web3(chain)
        slow_gas_price, average_gas_price, fast_gas_price = get_gas_price(w3)
        gas_prices = {'slow': slow_gas_price, 'average': average_gas_price, 'fast': fast_gas_price}
    except ValueError:
        return {'code': 400, 'message': 'Unsupported chain', 'data': []}, 200

    nonce = get_nonce(w3, address)

    # Load contract
    contract = w3.eth.contract(address=contract_address, abi=load_abi('ERC20.json'))

    # Calculate token amount in smallest unit
    decimals = contract.functions.decimals().call()
    token_amount = int(amount * (10 ** decimals))

    # Build transaction
    transfer_function = contract.functions.transfer(to_address, token_amount)
    estimated_gas = transfer_function.estimate_gas({
        'from': address,
        'gasPrice': gas_prices[speed]
    })

    tx = transfer_function.build_transaction({
        'nonce': nonce,
        'gas': estimated_gas,
        'gasPrice': gas_prices[speed],
        'chainId': w3.eth.chain_id
    })

    tx_hash = sign_and_send_transaction(w3, tx, private_key)
    if isinstance(tx_hash, tuple): 
        return tx_hash
    # Delete the private key from memory
    del private_key
    return tx_hash.hex()

def get_eth_balance_by_telegram_id(telegram_id, chain):
    user = User.query.filter_by(telegram_id=str(telegram_id)).first()
    if user is None:
        return None

    user_key = UserKey.query.filter_by(user_id=user.id).first()
    if user_key is None:
        return None

    try:
        w3 = get_web3(chain)
    except ValueError:
        return None
    balance = w3.eth.get_balance(user_key.public_address)
    balance_in_ether = w3.from_wei(balance, 'ether')

    if isinstance(balance_in_ether, Decimal):
        balance_in_ether = "{:.5f}".format(balance_in_ether)
    return balance_in_ether

def get_erc20_balance_by_telegram_id(telegram_id, chain, contract_address):

    user = User.query.filter_by(telegram_id=str(telegram_id)).first()
    if user is None:
        return None

    user_key = UserKey.query.filter_by(user_id=user.id).first()
    if user_key is None:
        return None

    try:
        w3 = get_web3(chain)
        contract = w3.eth.contract(address=contract_address, abi=load_abi('ERC20.json'))
    except ValueError:
        return None
    balance = contract.functions.balanceOf(user_key.public_address).call()
    decimals = contract.functions.decimals().call()
    balance_in_token = balance / (10 ** decimals)

    if isinstance(balance_in_token, Decimal):
        balance_in_token = "{:.5f}".format(balance_in_token)
    return balance_in_token

def save_user_key(user_id, eth_address, mnemonic):
    key = load_key()
    cipher_suite = Fernet(key)
    shares = split_secret(mnemonic.encode(), num_shares=3, threshold=2)
    encrypted_shares = [cipher_suite.encrypt(bytes(share)) for share in shares]

    user_key = UserKey(
        user_id=user_id,
        public_address=eth_address,
        private_key_share=encrypted_shares[0].hex(),
        private_key_share_1=encrypted_shares[1].hex(),
        method='normal', 
    )
    db.session.add(user_key)
    db.session.commit()

    return encrypted_shares[2].hex()

def add_point_transaction(user_id, quantity, transaction_type):
    transaction = PointTransaction(user_id=user_id, quantity=quantity, transaction_type=transaction_type)
    db.session.add(transaction)

def get_asset_balances(user_id):
    asset_types = ['BTC', 'ETH', 'MATIC']  
    balances = {asset_type: 0 for asset_type in asset_types}
    prices = {asset_type: float(get_random_prices(asset_type)) for asset_type in asset_types}
    total_assets = 0

    for asset_type in asset_types:
        asset_type_obj = AssetType.query.filter_by(name=asset_type).first()
        if asset_type_obj:
            asset = Asset.query.filter_by(user_id=user_id, asset_type_id=asset_type_obj.id).first()
            if asset:
                balances[asset_type] = float(asset.quantity)
                total_assets += balances[asset_type] * prices[asset_type]

    point_asset_type = AssetType.query.filter_by(name='POINT').first()
    if point_asset_type:
        point_asset = Asset.query.filter_by(user_id=user_id, asset_type_id=point_asset_type.id).first()
        if point_asset:
            balances['POINT'] = float(point_asset.quantity)
            total_assets += balances['POINT']

    return balances, total_assets, prices, asset_types

############################## tele-miniapp ############################

@app.route('/bot/tg_mini')
def tg_miniapps():
    return render_template('tg_miniapps.html')

@app.route('/bot/verify_mini_apps', methods=['GET'])
def verify_mini_apps():

    initData = request.args.get('initData')

    decodedInitData = unquote(initData)

    params = parse_qs(decodedInitData)

    auth_date = params.get('auth_date')[0]
    query_id = params.get('query_id')
    if query_id is not None:
        query_id = query_id[0]
    else:
        pass
    user = params.get('user')[0]
    received_hash = params.get('hash')[0]

    data_check_string = f"auth_date={auth_date}\nquery_id={query_id}\nuser={user}"

    secret_key = hmac.new("WebAppData".encode('utf-8'), TOKEN.encode('utf-8'),  hashlib.sha256).digest()

    computed_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()

    if received_hash == computed_hash:
        print("Data is from Telegram")

        user_data = json.loads(user)
        user_id = user_data['id']
        username = user_data.get('username')
        user_name = "@" + username if username else str(user_id)

        user = User.query.filter_by(telegram_id=str(user_id)).first()

        if user:
            print("User exists.")
            if user.username != user_name:
                print("Username changed.")
                user.username = user_name
                db.session.commit()
            login_user(user)
            check_tx_status_logic(user)
        else:
            logout_user()
    else:
        logout_user()

    return redirect('/bot/tg_posts')

@app.route('/bot/tg_posts')
def posts():
    page = request.args.get('page', 1, type=int)
    response = requests.get('http://localhost:5000/sellpost/get_all_posts', params={'page': page})
    if response.content:
        try:
            posts = response.json().get('data', {}).get('posts', [])
        except ValueError:
            print("Response is not JSON format.")
            posts = []
    else:
        print("Response is empty.")
        posts = []

    if current_user.is_authenticated:
        username = current_user.username
        balances, total_assets, prices, asset_types = get_asset_balances(current_user.id)
        user_orders = Order.get_recent_orders(current_user.id)
    else:
        username = 'anonymous'
        asset_types = ['BTC', 'ETH', 'POINT']  
        balances = {asset_type: 0 for asset_type in asset_types}
        total_assets = 0
        prices = {asset_type: 0 for asset_type in asset_types}

    return render_template('tg.html', 
                       posts=posts, 
                       username=username, 
                       balances=balances, 
                       total_assets=total_assets,
                       prices=prices,
                       asset_types=asset_types,
                       user_orders=user_orders)

@app.route('/bot/submit_market_order', methods=['POST'])
@login_required
def submit_market_order():
    try:
        order_data = request.get_json()
        symbol_name = order_data['symbol']
        asset_type = AssetType.query.filter_by(name=symbol_name).first()
        if asset_type is None:
            return {'error': f'no {symbol_name} '}, 400

        average_price = get_random_prices(symbol_name)

        total_value = float(order_data['quantity']) * average_price

        if float(order_data['quantity']) < get_decimal_value(symbol_name) or total_value > 100:
            return {'error': f'quantity must > { get_decimal_value(symbol_name) } and < 100 POINT'}, 400


        order = Order(
            side=order_data['side'],
            quantity=order_data['quantity'],
            filled_quantity=order_data['quantity'],
            user_id=current_user.id,
            asset_type_id=asset_type.id,
            price=average_price,
            orcal_price =average_price,
            symbol=asset_type.name,
            order_type='market'  
        )

        db.session.add(order)
        db.session.commit()
        return {'message': 'Market order submitted successfully'}, 201
    except Exception as e:
        db.session.rollback()  
        logger.error(str(e))
        return {'error': str(e)}, 400


@app.route('/bot/tg_login', methods=['GET'])
def tg_login():
    print("Received a GET request.")
    check_string = "auth_date={}\nfirst_name={}\nid={}\nphoto_url={}\nusername={}".format(
        request.args.get('auth_date'),
        request.args.get('first_name'),
        request.args.get('id'),
        request.args.get('photo_url'),
        request.args.get('username')
    )
    print(f"Check string: {check_string}")
    secret_key = hashlib.sha256(TOKEN.encode('utf-8')).digest()
    hmac_check = hmac.new(secret_key, msg=check_string.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
    print(f"HMAC check: {hmac_check}")
    if hmac_check == request.args.get('hash'):
        print("HMAC check passed.")
        user_id = request.args.get('id')
        username = request.args.get('username')
        user_name = "@" + username if username else str(user_id)
        print(f"User ID: {user_id}, Username: {user_name}")

        user = User.query.filter_by(telegram_id=str(user_id)).first()

        if user:
            print("User exists.")
            if user.username != user_name:
                print("Username changed.")
                user.username = user_name
                db.session.commit()
        else:
            print("User does not exist. PLS /start in tgbot first.")

        login_user(user) 
    else:
        logout_user()
    return redirect('/')

##############################telebot############################

def send_trade_keyboard(user_id, chat_id):
    with app.app_context():
        user = User.query.filter_by(telegram_id=str(user_id)).first()
        user_key = UserKey.query.filter_by(user_id=user.id).first() if user else None

        login_url = LoginUrl(url=LOGIN_URL, bot_username=BOT_USERNAME)    
        keyboard = InlineKeyboardMarkup()
        
        row0 = [InlineKeyboardButton(text="Your StarLight Wallet", callback_data="starlight_wallet")]
        row1 = [InlineKeyboardButton(text="Website", login_url=login_url)]
        row2 = [InlineKeyboardButton(text="Invitation link", callback_data="get_invitation_link"),
                InlineKeyboardButton(text="Security setting", callback_data="security_setting")]
              
        keyboard.row(*row0)
        keyboard.row(*row1)
        keyboard.row(*row2)

        user_key = UserKey.query.filter_by(user_id=user.id).first()
        eth_address = user_key.public_address if user_key else None

        info_text = (
            f"🚀 Welcome to PicWe Bot {user.username}\n"
            f"📈 Browse top traders' predictions of crypto\n"
            f"⏰ Make Real-time trades\n"
            f"📬 Your Wallet Address:\n{eth_address}\n"
        )

        bot.send_photo(chat_id, photo=open(PHOTO_PATH, 'rb'), reply_markup=keyboard, caption=info_text)

@app.route(f'/{TOKEN}', methods=['POST'])
def get_message():
    json_string = request.get_data().decode('utf-8')
    update = Update.de_json(json_string)
    bot.process_new_updates([update])
    return '', 200

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    user_id = message.from_user.id 
    user_name = '@' + message.from_user.username if message.from_user.username else str(user_id) 
    split_message = message.text.split("/start ")
    invitation_code = split_message[1] if len(split_message) > 1 else None

    with app.app_context():
        user = User.query.filter_by(telegram_id=str(user_id)).first()
        is_new_user = False

        if not user:
            is_new_user = True
            user = User(username=user_name, telegram_id=str(user_id), is_telegram_user=True)
            db.session.add(user)
            db.session.commit()

            mnemonic, eth_address, private_key = create_eth_wallet()
            hot_share = save_user_key(user.id, eth_address, mnemonic)
            del private_key
            del mnemonic
            if invitation_code:
                inviter = User.query.filter_by(invitation_code=invitation_code).first()
                if inviter:
                    user.inviter_id = inviter.id
                    db.session.commit()  

            user.generate_invitation_code()
            user.last_login_date = datetime.utcnow()
            db.session.commit()

        else:
            if user.username != user_name:
                user.username = user_name
                db.session.commit()

    try:
        send_trade_keyboard(message.from_user.id, message.chat.id)
        if is_new_user:
            bot.send_message(message.chat.id, f"hot fragment: {hot_share}\n it is used for importing fragments on the web end and resetting wallet fragments. Please keep it safe.")
    except Exception as e:
        logger.error("Error in bot start:", e)


@bot.callback_query_handler(func=lambda call: call.data == "main_index")
def main_index(call):
    bot.delete_message(call.message.chat.id, call.message.message_id)
    send_trade_keyboard(call.from_user.id, call.message.chat.id)

@bot.callback_query_handler(func=lambda call: call.data == "starlight_wallet")
def seth(call):
    try:
        with app.app_context():
            user = User.query.filter_by(telegram_id=str(call.from_user.id)).first()
            if user is None:
                bot.send_message(call.message.chat.id, "用户未找到")
                return

            check_tx_status_logic(user)

            ETH_balance = get_eth_balance_by_telegram_id(call.from_user.id, CHAIN_NAME)  # Replace 'ethereum_mainnet' with the actual chain
            POINT_balance = get_erc20_balance_by_telegram_id(call.from_user.id, CHAIN_NAME, pUSDT_address)
        if ETH_balance is None:
            bot.send_message(call.message.chat.id, "Unable to retrieve balance.")
            return

        keyboard = types.InlineKeyboardMarkup()

        row1 = [types.InlineKeyboardButton(text="Back to main menu", callback_data="main_index")]

        row2 = [types.InlineKeyboardButton(text="Deposit USDT to PicWe from StarLight wallet", callback_data="deposit")]

        row3 = [types.InlineKeyboardButton(text="Withdraw USDT from PicWe to StarLight wallet", callback_data="withdraw")]

        row4 = [types.InlineKeyboardButton(text=f"MATIC: {ETH_balance}", callback_data="no_callback"),
                types.InlineKeyboardButton(text="Send", callback_data="sending_eth")]
        
        row5 = [types.InlineKeyboardButton(text=f"USDT: {POINT_balance}", callback_data="no_callback"),
                types.InlineKeyboardButton(text="Send", callback_data="sending_point")]

        keyboard.row(*row1)
        keyboard.row(*row2)
        keyboard.row(*row3)
        keyboard.row(*row4)
        keyboard.row(*row5)
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=keyboard)
    except Exception as e:
        logger.error("Error in bot wallet:", e)

to_address_dict = {}
user_states = {}

@bot.callback_query_handler(func=lambda call: call.data == "sending_eth")
def ask_for_address(call):
    telegram_user_id = call.from_user.id
    user_states[telegram_user_id] = "sending_eth"
    msg = bot.send_message(call.message.chat.id, "Please enter the destination address:")
    bot.register_next_step_handler(msg, ask_for_amount)

def ask_for_amount(message):
    telegram_user_id = message.from_user.id
    if user_states.get(telegram_user_id) != "sending_eth":
        return
    to_address_dict[telegram_user_id] = message.text
    msg = bot.send_message(message.chat.id, "Please enter the amount to send:")
    bot.register_next_step_handler(msg, send_eth)

def send_eth(message):
    telegram_user_id = message.from_user.id
    if user_states.get(telegram_user_id) != "sending_eth":
        return
    try:
        amount = float(message.text)    
    except ValueError:
        bot.send_message(message.chat.id, "Invalid amount. Please enter again.")
        return

    try:
        with app.app_context():
            user = User.query.filter_by(telegram_id=str(telegram_user_id)).first()
            if user is None:
                bot.send_message(telegram_user_id, "User not found.")
                return
            to_address = to_address_dict.get(telegram_user_id)
            result = bot_transfer_ether(user.id, to_address, amount, 'fast', CHAIN_NAME)
            # print(result)
			
    except Exception as e:
        logger.error("Error in bot_transfer_ether:", e)
        bot.send_message(message.chat.id, "Transfer failed: Internal error.")
        return

    tx_url = f"{TX_BASE_URL}{result}"
    message_text = f"Transfer successful! Transaction hash:[{result}]({tx_url})"
    bot.send_message(message.chat.id, message_text, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "sending_point")
def ask_for_address_point(call):
    telegram_user_id = call.from_user.id
    user_states[telegram_user_id] = "sending_point"
    msg = bot.send_message(call.message.chat.id, "Please enter the destination address to send Token to:")
    bot.register_next_step_handler(msg, ask_for_amount_point)

def ask_for_amount_point(message):
    telegram_user_id = message.from_user.id
    if user_states.get(telegram_user_id) != "sending_point":
        return
    to_address_dict[message.from_user.id] = message.text
    msg = bot.send_message(message.chat.id, "Please enter the amount of Token to send:")
    bot.register_next_step_handler(msg, send_point)

def send_point(message):
    telegram_user_id = message.from_user.id

    if user_states.get(telegram_user_id) != "sending_point":
        return
    
    try:
        # Convert the message text to a float
        amount = float(message.text)
    except ValueError:
        bot.send_message(message.chat.id, "Invalid amount. Please enter again.")
        return
    try:
        with app.app_context():
            user = User.query.filter_by(telegram_id=str(telegram_user_id)).first()
            if user is None:
                bot.send_message(telegram_user_id, "User not found.")
                return
            result = bot_transfer_erc20(user.id, to_address_dict[telegram_user_id], amount, 'fast', CHAIN_NAME, pUSDT_address)
    except Exception as e:
        logger.error("Error in bot_transfer_point:", e)
        bot.send_message(message.chat.id, "Transfer failed: Internal error.")
        return
    to_address_dict.pop(telegram_user_id, None)
    tx_url = f"{TX_BASE_URL}{result}"
    message_text = f"Transfer successful! Transaction hash:[{result}]({tx_url})"
    bot.send_message(message.chat.id, message_text, parse_mode="Markdown")


@bot.callback_query_handler(func=lambda call: call.data == "deposit")
def ask_for_amount_usdt(call):
    telegram_user_id = call.from_user.id
    speed = 'fast'
    chain = CHAIN_NAME 

    user_states[telegram_user_id] = "depositing"

    try:
        with app.app_context():
            user = User.query.filter_by(telegram_id=str(telegram_user_id)).first()
            if user is None:
                bot.send_message(telegram_user_id, "User not found")
                return

            # Call approve_point_token_logic
            approve_result = approve_point_token_logic(user, 1, speed, chain, "pUSDT.json", pUSDT_address, simple_pUSDT_address, 'db',6)
            if approve_result[0]['code'] == 200 and approve_result[0]['message'] == 'Sufficient allowance':
                # If allowance is sufficient, ask for the deposit amount
                msg = bot.send_message(call.message.chat.id, "Please enter the amount of Token to deposit:")
                bot.register_next_step_handler(msg, deposit_usdt)
            else:
                # If allowance is insufficient, return the tx link from approve_point_token_logic
                bot.send_message(telegram_user_id, "Insufficient contract allowance, opening allowance for the contract. Transaction hash:[{}]({})".format(approve_result[0]['data']['transaction_hash'], TX_BASE_URL + approve_result[0]['data']['transaction_hash']), parse_mode="Markdown")
    except Exception as e:
        logger.error("Error in deposit:", e)
        bot.send_message(telegram_user_id, "Deposit failed: Internal error")
        return

def deposit_usdt(message):
    telegram_user_id = message.from_user.id
    speed = 'fast'
    chain = CHAIN_NAME 
    if user_states.get(telegram_user_id) != "depositing":
        return
    try:
        # Convert the message text to a float
        amount = float(message.text)     
    except ValueError:
        bot.send_message(message.chat.id, "Invalid amount. Please enter again.")
        return
    
    try:
        with app.app_context():
            user = User.query.filter_by(telegram_id=str(telegram_user_id)).first()
            if user is None:
                bot.send_message(telegram_user_id, "User not found")
                return
           
            # Call open_channel_logic
            open_result = open_channel_logic(user, chain, amount, speed, "simple.json", simple_pUSDT_address, 'db', 6)
            if open_result[0]['code'] == 200:
                bot.send_message(telegram_user_id, "Deposit successful! Transaction hash:[{}]({})".format(open_result[0]['data']['transaction_hash'], TX_BASE_URL + open_result[0]['data']['transaction_hash']), parse_mode="Markdown")
            else:
                bot.send_message(telegram_user_id, "Deposit failed: {}".format(open_result[0]['message']))
            return
    except Exception as e:
        logger.error("Error in deposit:", e)
        bot.send_message(telegram_user_id, "Deposit failed: Internal error")
        return

    
@bot.callback_query_handler(func=lambda call: call.data == "withdraw")
def ask_for_withdraw_amount(call):
    telegram_user_id = call.from_user.id
    user_states[telegram_user_id] = "withdrawing"
    msg = bot.send_message(call.message.chat.id, "Please enter the amount of Token to withdraw:")
    bot.register_next_step_handler(msg, withdraw_usdt)

def withdraw_usdt(message):
    telegram_user_id = message.from_user.id
    speed = 'fast'
    chain = CHAIN_NAME 

    if user_states.get(telegram_user_id) != "withdrawing":
        return
    try:
        # Convert the message text to a float
        amount = float(message.text)     
    except ValueError:
        bot.send_message(message.chat.id, "Invalid amount. Please enter again.")
        return
    
    try:
        with app.app_context():
            user = User.query.filter_by(telegram_id=str(telegram_user_id)).first()
            if user is None:
                bot.send_message(telegram_user_id, "User not found")
                return
           
            # Call withdraw_part_point_logic
            withdraw_result = withdraw_part_point_logic(user, amount, speed, chain, "simple.json", simple_pUSDT_address, 'db',6)

            if withdraw_result[0]['code'] == 200:
                bot.send_message(telegram_user_id, "Withdrawal successful! Transaction hash:[{}]({})".format(withdraw_result[0]['data']['transaction_hash'], TX_BASE_URL + withdraw_result[0]['data']['transaction_hash']), parse_mode="Markdown")
            else:
                bot.send_message(telegram_user_id, "Withdrawal failed: {}".format(withdraw_result[0]['message']))
            return
    except Exception as e:
        logger.error("Error in withdraw:", e)
        bot.send_message(telegram_user_id, "Withdrawal failed: Internal error")
        return

@bot.callback_query_handler(func=lambda call: call.data == "get_invitation_link")
def get_invitation_link(call):
    with app.app_context():
        user = User.query.filter_by(telegram_id=str(call.from_user.id)).first()
        if user is None:
            bot.send_message(call.message.chat.id, "User not found.")
            return
    invitation_link = f"https://t.me/picwe_bot?start={user.invitation_code}"
    bot.send_message(call.message.chat.id, invitation_link)
