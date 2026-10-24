# tara-lite

用于概念阶段的汽车网络安全威胁分析（TARA）小工具。输入资产和威胁 JSON，输出可排序的风险分数、风险等级和建议处理优先级，帮助把 R155/ISO 21434 的讨论从表格搬进版本库。

使用：python tara.py examples/threats.json。评分采用 severity * likelihood，并用阈值映射 LOW、MEDIUM、HIGH、CRITICAL。它是工程协作工具，不是认证结论。

安全论证常散落在会议纪要和受控表格中，变更难审计。纯文本输入、确定性评分和 JSON 输出便于代码评审、CI 和后续导入更完整的治理系统。

## 许可证

MIT
