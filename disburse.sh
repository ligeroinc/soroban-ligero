#!/bin/bash

CONTRACT_ID="CDTLYWL6XP6DKKBB6F5QKFG2VP6CI3K4YV5EJDIQTTD6RV5C6LCXEWTX"
SOURCE_ACCOUNT="relayer"
FUNCTION_NAME="disburse"
RELAYER_ADDRESS="GAFLKJBXLSMYMOSBDXSWOKGYXQGZFVE5QTF6X3FKR6YVAPDDGFKVV2DI"
XLM_ADDRESS="CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"


stellar contract invoke --id ${CONTRACT_ID} --source-account alice --network testnet -- version --to RPC 
# script to disburse funds

#stellar contract invoke --id ${CONTRACT_ID} --source-account alice --network testnet -- version --to RPC 
#stellar contract invoke --id CDTLYWL6XP6DKKBB6F5QKFG2VP6CI3K4YV5EJDIQTTD6RV5C6LCXEWTX --source-account relayer --network testnet --fnc disburse --arg1 GAFLKJBXLSMYMOSBDXSWOKGYXQGZFVE5QTF6X3FKR6YVAPDDGFKVV2DI --arg2 1 --arg3 CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC --arg4 GAFLKJBXLSMYMOSBDXSWOKGYXQGZFVE5QTF6X3FKR6YVAPDDGFKVV2DI --arg5 1 --to RPC

#stellar contract invoke \
#  --id ${CONTRACT_ID}
#  --source-account ${SOURCE_ACCOUNT} \
#  --network testnet \
#  --fnc ${FUNCTION_NAME} \
#  --arg1 ${RELAYER_ADDRESS} \
#  --arg2 1 \
#  --arg3 ${XLM_ADDRESS} \
#  --arg4 ${RELAYER_ADDRESS} \
#  --arg5 1 \
#  --to RPC
