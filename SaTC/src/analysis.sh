#!/bin/bash

# ������
if [ $# -ne 1 ]; then
    echo "�÷�: $0 <input1>"
    echo "ʾ��: $0 firmware_name"
    exit 1
fi

INPUT1="$1"
RESULT_FILE="../../test/${INPUT1}/keyword_extract_result/detail/Clustering_result_v2.result"

echo "��ʼ����: $INPUT1"

# ����1: ִ��python satc.py����
echo "����1: ִ��satc.py����..."
python satc.py -d "../../../greenhouse/firmware/${INPUT1}" -o "../../test/${INPUT1}" --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof

# ��������Ƿ�ɹ�ִ��
if [ $? -ne 0 ]; then
    echo "����: satc.pyִ��ʧ��"
    exit 1
fi

# ����2: ������ļ��Ƿ����
echo "����2: ������ļ�..."
if [ ! -f "$RESULT_FILE" ]; then
    echo "����: ����ļ�������: $RESULT_FILE"
    exit 1
fi

# ����3: ��ȡProgram name��ȡ����·��
echo "����3: ��ȡ����·��..."
PROGRAM_PATH=$(grep "Program name" "$RESULT_FILE" | head -1 | sed 's/.*Program name[[:space:]]*:[[:space:]]*//')

if [ -z "$PROGRAM_PATH" ]; then
    echo "����: �޷��ҵ�Program name"
    exit 1
fi

echo "�ҵ�����·��: $PROGRAM_PATH"

# ����4: ���Ƴ����ļ�
echo "����4: ���Ƴ����ļ�..."
cp "$PROGRAM_PATH" "../../test/${INPUT1}/"

if [ $? -ne 0 ]; then
    echo "����: ���Ƴ����ļ�ʧ��"
    exit 1
fi

# ����5: ��ȡbinary����
BINARY_NAME=$(basename "$PROGRAM_PATH")
echo "�������ļ���: $BINARY_NAME"

# ����6: ��ȡ��һ��Hits Para�������
echo "����6: ��ȡHits Para����..."
HITS_CONTENT=$(grep "Hits Para :" "$RESULT_FILE" | head -1 | sed 's/.*Hits Para[[:space:]]*:[[:space:]]*//')

if [ -z "$HITS_CONTENT" ]; then
    echo "����: �޷��ҵ�Hits Para����"
    HITS_CONTENT=""
fi

# ����7: д�뵽ָ���ļ�
OUTPUT_FILE="../../test/${INPUT1}/${BINARY_NAME}_origin_strs.txt"
echo "����7: д������ $OUTPUT_FILE"
echo "$HITS_CONTENT" > "$OUTPUT_FILE"

# ����8: �л�Ŀ¼��ִ��LLMATaint.py
echo "����8: ִ��LLMATaint.py..."
cd ../..

python LLMATaint.py -b "./test/${INPUT1}/${BINARY_NAME}" -p False -t ci -o "./test/${INPUT1}" -m V3

if [ $? -ne 0 ]; then
    echo "����: LLMATaint.pyִ��ʧ��"
    exit 1
fi

echo "���в������!"
echo "������ļ�: $INPUT1"
echo "�������ļ�: $BINARY_NAME"
echo "���������: ./test/${INPUT1}/"