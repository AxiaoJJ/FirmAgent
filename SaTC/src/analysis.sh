#!/bin/bash

# 检查参数
if [ $# -ne 1 ]; then
    echo "用法: $0 <input1>"
    echo "示例: $0 firmware_name"
    exit 1
fi

INPUT1="$1"
RESULT_FILE="../../test/${INPUT1}/keyword_extract_result/detail/Clustering_result_v2.result"

echo "开始处理: $INPUT1"

# 步骤1: 执行python satc.py命令
echo "步骤1: 执行satc.py分析..."
python satc.py -d "../../../greenhouse/firmware/${INPUT1}" -o "../../test/${INPUT1}" --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof

# 检查命令是否成功执行
if [ $? -ne 0 ]; then
    echo "错误: satc.py执行失败"
    exit 1
fi

# 步骤2: 检查结果文件是否存在
echo "步骤2: 检查结果文件..."
if [ ! -f "$RESULT_FILE" ]; then
    echo "错误: 结果文件不存在: $RESULT_FILE"
    exit 1
fi

# 步骤3: 读取Program name获取程序路径
echo "步骤3: 提取程序路径..."
PROGRAM_PATH=$(grep "Program name" "$RESULT_FILE" | head -1 | sed 's/.*Program name[[:space:]]*:[[:space:]]*//')

if [ -z "$PROGRAM_PATH" ]; then
    echo "错误: 无法找到Program name"
    exit 1
fi

echo "找到程序路径: $PROGRAM_PATH"

# 步骤4: 复制程序文件
echo "步骤4: 复制程序文件..."
cp "$PROGRAM_PATH" "../../test/${INPUT1}/"

if [ $? -ne 0 ]; then
    echo "错误: 复制程序文件失败"
    exit 1
fi

# 步骤5: 提取binary名称
BINARY_NAME=$(basename "$PROGRAM_PATH")
echo "二进制文件名: $BINARY_NAME"

# 步骤6: 提取第一个Hits Para后的内容
echo "步骤6: 提取Hits Para内容..."
HITS_CONTENT=$(grep "Hits Para :" "$RESULT_FILE" | head -1 | sed 's/.*Hits Para[[:space:]]*:[[:space:]]*//')

if [ -z "$HITS_CONTENT" ]; then
    echo "警告: 无法找到Hits Para内容"
    HITS_CONTENT=""
fi

# 步骤7: 写入到指定文件
OUTPUT_FILE="../../test/${INPUT1}/${BINARY_NAME}_origin_strs.txt"
echo "步骤7: 写入结果到 $OUTPUT_FILE"
echo "$HITS_CONTENT" > "$OUTPUT_FILE"

# 步骤8: 切换目录并执行LLMATaint.py
echo "步骤8: 执行LLMATaint.py..."
cd ../..

python LLMATaint.py -b "./test/${INPUT1}/${BINARY_NAME}" -p False -t ci -o "./test/${INPUT1}" -m V3

if [ $? -ne 0 ]; then
    echo "错误: LLMATaint.py执行失败"
    exit 1
fi

echo "所有步骤完成!"
echo "处理的文件: $INPUT1"
echo "二进制文件: $BINARY_NAME"
echo "结果保存在: ./test/${INPUT1}/"