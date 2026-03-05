# Solidity Smart Contract Vulnerability Database

SOLIDITY_VULNS = {
    "Reentrancy": {
        "cve": "CWE-841",
        "severity": "CRITICAL",
        "description": "重入攻击 - 外部合约回调导致重复执行",
        "example": "The DAO攻击",
        "pattern": ["call.value", "transfer", "send"],
        "fix": "Checks-Effects-Interactions模式"
    },
    "Integer_Overflow": {
        "cve": "CWE-190", 
        "severity": "HIGH",
        "description": "整数溢出/下溢",
        "example": "batchTransfer漏洞",
        "pattern": ["+", "-", "*", "/"],
        "fix": "SafeMath库或Solidity 0.8+"
    },
    "Access_Control": {
        "cve": "CWE-284",
        "severity": "HIGH", 
        "description": "访问控制未正确限制",
        "pattern": ["public", "external"],
        "fix": "require/onlyOwner修饰符"
    },
    "Front_Running": {
        "cve": "CWE-362",
        "severity": "MEDIUM",
        "description": "抢先交易 - 交易排序操纵",
        "pattern": ["gas price", "gasLimit"],
        "fix": "提交-揭示方案"
    },
    "Flash_Loan": {
        "cve": None,
        "severity": "CRITICAL",
        "description": "闪电贷攻击 - 即时借贷操纵价格",
        "pattern": ["flashLoan", "swap", "liquidity"],
        "fix": "价格预言机/时间加权平均"
    },
    "Oracle_Manipulation": {
        "cve": None,
        "severity": "HIGH",
        "description": "预言机数据操纵",
        "pattern": ["getReserves", "priceFeed"],
        "fix": "多源预言机/Chainlink"
    },
    "Signature_Replay": {
        "cve": "CWE-347",
        "severity": "MEDIUM",
        "description": "签名重放攻击",
        "pattern": ["ecrecover", "signature"],
        "fix": "nonce验证/过期时间"
    },
    "Delegatecall": {
        "cve": "CWE-115",
        "severity": "HIGH",
        "description": "委托调用上下文劫持",
        "pattern": ["delegatecall", "library"],
        "fix": "验证library地址"
    },
    "Block_Timestamp": {
        "cve": None,
        "severity": "MEDIUM",
        "description": "区块时间戳操纵",
        "pattern": ["block.timestamp", "now"],
        "fix": "不要依赖时间做关键决策"
    },
    "Uninitialized_Storage": {
        "cve": "CWE-457",
        "severity": "HIGH",
        "description": "未初始化存储指针",
        "pattern": ["storage", "memory"],
        "fix": "正确初始化变量"
    },
}

print("Solidity漏洞库:")
for name, info in SOLIDITY_VULNS.items():
    print(f"  {name}: {info['severity']}")

print(f"\n共 {len(SOLIDITY_VULNS)} 种漏洞")
