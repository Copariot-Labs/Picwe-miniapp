
network = 'polygon'
net_type = 'mainnet'

# 定义网络参数
networks = {
    'polygon': {
        'mainnet': {
            'CHAIN_NAME': 'polygon_mainnet',
            'TX_BASE_URL': 'https://polygonscan.com/tx/',
            'TOKEN': '6210570739:AAG9FqWTHrLKXwjsZoQuKIMGYDCpvpn-TGY',
            'simple_pUSDT_address': '0x94Daf67052B5fe73211105E3587CB645E5a874e3',
            'pUSDT_address': '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',
        },
        'testnet': {
            'CHAIN_NAME': 'polygon_mumbai',
            'TX_BASE_URL': 'https://mumbai.polygonscan.com/tx/',
            'TOKEN': '6651889657:AAGmEahuwzrg7zXMVXKnIuLNGR6jcaGy0x0',
            'simple_pUSDT_address': '0x0ae64C11D072d7161068AD128f3EDe07F36f3fEE',
            'pUSDT_address': '0xd1b9C2118075fF94c0bE63574159301F1609c5A4',
        }
    },
    'ethereum': {
        'mainnet': {
            'CHAIN_NAME': 'ethereum_mainnet',
            'TX_BASE_URL': 'https://etherscan.io/tx/',
            'TOKEN': 'YOUR_ETHEREUM_MAINNET_TOKEN',
            'simple_pUSDT_address': 'YOUR_ETHEREUM_MAINNET_SIMPLE_PUSDT_ADDRESS',
            'pUSDT_address': 'YOUR_ETHEREUM_MAINNET_PUSDT_ADDRESS',
        },
        'testnet': {
            'CHAIN_NAME': 'ethereum_goerli',
            'TX_BASE_URL': 'https://goerli.etherscan.io/tx/',
            'TOKEN': 'YOUR_ETHEREUM_GOERLI_TOKEN',
            'simple_pUSDT_address': 'YOUR_ETHEREUM_GOERLI_SIMPLE_PUSDT_ADDRESS',
            'pUSDT_address': 'YOUR_ETHEREUM_GOERLI_PUSDT_ADDRESS',
        }
    }
}

params = networks[network][net_type]
CHAIN_NAME = params['CHAIN_NAME']
TX_BASE_URL = params['TX_BASE_URL']
TOKEN = params['TOKEN']
simple_pUSDT_address = params['simple_pUSDT_address']
pUSDT_address = params['pUSDT_address']

PR = ''
