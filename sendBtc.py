from hdwallet import BIP141HDWallet
# from hdwallet.utils import generate_mnemonic
from hdwallet.symbols import BTCTEST as SYMBOL
from bitcoinutils.keys import P2pkhAddress, P2wpkhAddress, PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction , TxInput , TxOutput, TxWitnessInput
import time
import requests
setup('testnet')

def checkPrevInput(tx: str) -> bool:
  """
    Params:
    tx = txID
  """
  txData = requests.get(url=f'https://mempool.space/testnet/api/tx/{tx}')
  dato = txData.json()
  typeOf = dato['vin'][0]['prevout']['scriptpubkey_type']
  print(typeOf)
  if typeOf == 'v0_p2wpkh':
    return True
  else:
    return False

def to_usd(ammount: float):
  """
    CONVERT BTC to USD and print:
    -------
    >>> Fee in BTC: 0.00002800 
    >>> Value of 0.00002800 BTC is $1.78 USD
  """
  # Return current price of 1 BTC in USD
  try:
    btcPrice = requests.get(url="https://mempool.space/api/v1/prices")
    pirceList = btcPrice.json()
    # Calcular el valor en USD
    usdAmmount = ammount * pirceList['USD']
    # Imprimir el resultado
    print(f'In BTC: {ammount:.8f}')
    print(f"Value of {ammount:.8f} BTC is ${usdAmmount:.2f} USD")
    return None
  except Exception as e:
    print(e)

def lessFees(amountSAT: int) -> int:
  """
    TAKE THE AMMOUNT IN SAT AND RETUN THE AMMOUNT LESS FEE (fastestFee) IN SATOSHIS
  """
  # ----------------------------------TAMAÑO DE TRANSACCION-------------------------------------------
  # Legacy Address (P2PKH): (Numero de inputs × 148) + (Numero de outputs × 34) + 10
  # Pay-to-Script-Hash (P2SH): (Numero de inputs × 92) + (Numero de outputs × 34) + 10
  # Pay-to-Witness-Public-Key-Hash (P2WPKH): (Numero de inputs × 68) + (Numero de outputs × 31) + 10
  # Pay-to-Witness-Script-Hash (P2WSH): (Numero de inputs × 68) + (Numero de outputs × 43) + 10
  # ----------------------------------TARIFA----------------------------------------------------------
  # Tarifa = Tamaño de la transaccion × Tarifa por byte
  try: #  "https://mempool.space/api/v1/fees/recommended"   "https://mempool.space/testnet/api/v1/fees/recommended"
    recommendedFees = requests.get(url="https://mempool.space/testnet/api/v1/fees/recommended")
    feeData = recommendedFees.json()
    # (1 INPUT = 68) + (2 OUTPUS = 62) + 10 = 140
    lesFeeSAT = 140 * feeData["fastestFee"]
    inBTC = 0.00000001 * lesFeeSAT
    print(f'Fee SAT: {lesFeeSAT}')
    print(f'Ammount SAT: {amountSAT}')
    to_usd(float(inBTC))
    ammountLessFEE = amountSAT - lesFeeSAT
    return ammountLessFEE
  except Exception as e:
    print(e)

def verifyAdress() -> str:                            #   3
  while True:
    addressTo = str(input("Address to send the btc: "))
    try:
      validation = requests.get(url=f"https://mempool.space/testnet/api/v1/validate-address/{addressTo}")
      dataInfo = validation.json()
      if dataInfo["isvalid"] == True:
        print(f'Address found {dataInfo}')
        if dataInfo['isscript'] == False and dataInfo['iswitness'] == False:
          addresType = 'legacy'
          return addressTo, addresType
        elif dataInfo['isscript']:
          addresType = 'script'
          return addressTo, addresType
        elif dataInfo['iswitness']:
          addresType = 'witness'
          return addressTo, addresType
      else:
        print("Address not valid, it does not exist")
    except Exception as e:
      print(e)

def verifyTransaction(address: str):                  #   2
  failedAttempts = 0
  while failedAttempts != 3:
    try:
      getUTXO = requests.get(url=f'https://mempool.space/testnet/api/address/{address}/utxo')
      dataInfo = getUTXO.json()
      if dataInfo:
        if dataInfo[0]["status"]["confirmed"] == True:
          print("Transaction recibed")
          return str(dataInfo[0]["txid"]), int(dataInfo[0]["vout"]), int(dataInfo[0]["value"])
          # print(str(dataInfo[0]["txid"]), int(dataInfo[0]["vout"]), int(dataInfo[0]["value"]))
      else:
        print("There is not transaction recibed")
        print(dataInfo)
        failedAttempts += 1
    except Exception as e:
        print(f"Error request: {e}")
    # Esperar 10 minutos antes de realizar la próxima solicitud
    time.sleep(600)  # 600 segundos = 10 minutos

def sendBTC_inputP2WPKH_toP2PKH(pubToHash160: str, pubTohex: str, txId: str, vout: int, amount: int, addressTo: str, wif: str):
  """
  Send to a P2PKH (legacy) with an segwit address.
  -------
  >>> Raw transaction:
  "0200000000010178f18710b98bfc06195a1cec70fd8a0228fcf81fd8fae30ceab6495cff67219b0100000000ffffffff011ad20000000000001976a914ede4cbdc5c292e6aa5bb9be1dfa5b970a4e7309688ac00000000"

  >>> txin:
  >>> {'txid': '9b2167ff5c49b6ea0ce3fad81ff8fc28028afd70ec1c5a1906fc8bb91087f178', 'txout_index': 1, 'script_sig': [], 'sequence': 'ffffffff'}
  
  >>> txOut:
  >>> {'amount': 53786, 'script_pubkey': ['OP_DUP', 'OP_HASH160', 'ede4cbdc5c292e6aa5bb9be1dfa5b970a4e73096', 'OP_EQUALVERIFY', 'OP_CHECKSIG']}
  
  >>> Raw signed transaction:
  "0200000000010178f18710b98bfc06195a1cec70fd8a0228fcf81fd8fae30ceab6495cff67219b0100000000ffffffff011ad20000000000001976a914ede4cbdc5c292e6aa5bb9be1dfa5b970a4e7309688ac024730440220690a21e14f6ec4bdc581bf6ff3f2b2d0e1b27667cbddbd6f52a3371c847a0061022035cf21938b3b42d69d94d05bc388d273d30eea3109f9cf7ccf70de24689b0c6901210223a55fd2e969a49014e14ba3fe22b1ae1cf7207738b5a052f8f01c1209dd7ad500000000"
  """
  # ---------------------------------ScriptPubKey--------------------------------------------
  # create transaction input from tx id of UTXO
  txin = TxInput(txId, vout)
  toAddr = P2pkhAddress(addressTo)
  amountToSend = lessFees(amount)
  txOut = TxOutput(amountToSend, toAddr.to_script_pub_key())
  # TxOutput(to_satoshis(0.29), Script(['OP_DUP', 'OP_HASH160',change_addr.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']))
  # if at least a single input is segwit we need to set has_segwit=True
  tx = Transaction([txin], [txOut], has_segwit=True)
  print("\nRaw transaction:\n" + tx.serialize())
  print("\ntxin:\n", txin)
  print("\ntoAddr:\n", toAddr.to_string())
  print("\ntxOut:\n", txOut)
  # ---------------------------------SignatureScript------------------------------------------
  # script code required for signing; for p2wpkh it is the same as p2pkh
  script_code = Script(['OP_DUP', 'OP_HASH160', pubToHash160,'OP_EQUALVERIFY', 'OP_CHECKSIG'])
  priv = PrivateKey(wif)
  sig = priv.sign_segwit_input(tx, 0, script_code , amount)
  tx.witnesses.append(TxWitnessInput([sig, pubTohex]))
  # print raw signed transaction ready to be broadcasted
  print("\nRaw signed transaction:\n" + tx.serialize())
  print("\nTxId:", tx.get_txid())
  envio = requests.post(url='https://mempool.space/testnet/api/tx', data=tx.serialize())
  print(envio.status_code)
  print(envio.text)

def sendBTC_inputP2WPKH_toP2WPKH(pubToHash160: str, pubTohex: str, txId: str, vout: int, amount: int, addressTo: str, wif: str):
  """
  Send to a P2WPKH (segwit) with an segwit address.
  -------
  >>> Raw transaction:
  "02000000000101736b6169823da66132fb7e12819acf0f9f36f2eb9a8d1a5fab7208e0707703450000000000ffffffff01bc0e0100000000001600143deedeeef00adcee76b1e6a6c5141ad4932d929700000000"

  >>> txin:
  >>> {'txid': '45037770e00872ab5f1a8d9aebf2369f0fcf9a81127efb3261a63d8269616b73', 'txout_index': 0, 'script_sig': [], 'sequence': 'ffffffff'}
  
  >>> txOut:
  >>> {'amount': 69308, 'script_pubkey': ['OP_0', '3deedeeef00adcee76b1e6a6c5141ad4932d9297']}
  
  >>> Raw signed transaction:
  "02000000000101736b6169823da66132fb7e12819acf0f9f36f2eb9a8d1a5fab7208e0707703450000000000ffffffff01bc0e0100000000001600143deedeeef00adcee76b1e6a6c5141ad4932d929702473044022069db4396169b9d645a640fd87952b056d500397692ed3915942768f0ba8013c302207fae2bc86faa25c038a36cf05d854ae99c3746b7249d94836388c0930a85f8d701210216c8fa9e97aa7ca03b806ac0147583d8b1a7e2e414c359f1c53e5f7db1c90a3100000000"
  """
  # ---------------------------------ScriptPubKey--------------------------------------------
  txin = TxInput(txId, vout)
  toAddr = P2wpkhAddress(addressTo)
  amountToSend = lessFees(amount)
  txOut = TxOutput(amountToSend, toAddr.to_script_pub_key())
  # TxOutput(to_satoshis(0.29), Script(['OP_DUP', 'OP_HASH160',change_addr.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG']))
  # if at least a single input is segwit we need to set has_segwit=True
  tx = Transaction([txin], [txOut], has_segwit=True)
  print("\nRaw transaction:\n" + tx.serialize())
  print("\ntxin:\n", txin)
  print("\ntoAddr:\n", toAddr.to_string())
  print("\ntxOut:\n", txOut)
  # ---------------------------------SignatureScript------------------------------------------
  script_code = Script(['OP_DUP', 'OP_HASH160', pubToHash160,'OP_EQUALVERIFY', 'OP_CHECKSIG'])
  priv = PrivateKey(wif)
  sig = priv.sign_segwit_input(tx, 0, script_code , amount)
  tx.witnesses.append(TxWitnessInput([sig, pubTohex]))
  # print raw signed transaction ready to be broadcasted
  print("\nRaw signed transaction:\n" + tx.serialize())
  print("\nTxId:", tx.get_txid())
  envio = requests.post(url='https://mempool.space/testnet/api/tx', data=tx.serialize())
  print(envio.status_code)
  print(envio.text)

def walletFactory(pathNo: int = 0) -> None:            #   1
  # Choose strength 128, 160, 192, 224 or 256
  # STRENGTH: int = 256  # Default is 128
  # Generate new entropy hex string
  # MNEMONIC: str = generate_mnemonic(strength=STRENGTH)
  MNEMONIC = "brass park notice wagon tobacco you alley zebra fruit vacant later smile clap unit credit"
  # Secret passphrase for mnemonic

  # Initialize Bitcoin mainnet HDWallet
  hdwallet: BIP141HDWallet = BIP141HDWallet(symbol=SYMBOL, path=f"m/0/0/0'/0'/0'/0/{pathNo}")
  # Get Bitcoin HDWallet from entropy
  # hdwallet.from_entropy(
  #     entropy=ENTROPY, passphrase=PASSPHRASE
  # )
  hdwallet.from_mnemonic(mnemonic=MNEMONIC)

  # Derivation from path
  # hdwallet.from_path("m/44'/0'/0'/0/0")
  # Or derivation from index
  print(hdwallet.p2wpkh_address())
  # Print all Bitcoin HDWallet information's
  # print(json.dumps(hdwallet.dumps(), indent=4, ensure_ascii=False))
  txid, vout, amountInSat = verifyTransaction(hdwallet.p2wpkh_address())

  addressTo, addresType = verifyAdress()
  if addresType == 'legacy':
    sendBTC_inputP2WPKH_toP2PKH(pubToHash160=hdwallet.hash(), 
              pubTohex=hdwallet.compressed(), 
              txId=txid, vout=vout, 
              amount=amountInSat, 
              addressTo=addressTo,
              wif=hdwallet.wif()
              )
  # elif dataInfo['isscript']:
  #   addresType = 'script'
  elif addresType == 'witness':
    sendBTC_inputP2WPKH_toP2WPKH(pubToHash160=hdwallet.hash(),
              pubTohex=hdwallet.compressed(), 
              txId=txid, vout=vout, 
              amount=amountInSat, 
              addressTo=addressTo,
              wif=hdwallet.wif()
              )

walletFactory(1)
# 0-tb1q8hhdamhsptwwua43u6nv29q66jfjmy5husndyh 1-tb1qzepndvmrvp033med7mvfa8sqnjnfl80zt2qhk4