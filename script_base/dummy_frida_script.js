/*
 * dummy_frida_script.js
 * 一个用于演示 FridaScriptExecutor 用法的简单 Frida 脚本。
 */

// 一个返回结果的函数
function getSomeValue(multiplier) {
    console.log(`[JS] getSomeValue called with multiplier: ${multiplier}`);
    const result = 42 * multiplier;
    console.log(`[JS] Calculation result: ${result}`);
    
    // 使用 send 将结果发送回 Python
    // 'type': 'result' 是一个约定，用于告知 Python 这是期望的返回值
    send({
        type: 'result',
        data: result 
    });
}

// 一个只执行操作，不返回结果的函数
function performAction(actionName) {
    console.log(`[JS] Performing action: '${actionName}'`);
    
    // 操作完成后，可以发送一个 'finish' 消息
    // 这可以让 Python 的 call_rpc(..., wait_for_result=True) 结束等待
    send({
        type: 'finish',
        message: `Action '${actionName}' completed.`
    });
}

// 导出函数，以便 Python 可以调用
rpc.exports = {
    getSomeValue: getSomeValue,
    performAction: performAction
};
