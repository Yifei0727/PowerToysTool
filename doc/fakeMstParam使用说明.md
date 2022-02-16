## MST 验证码伪数据生成工具使用说明

### 环境依赖
`python2.7` 或 `python3.4` 以上 建议 使用`python3`

### 执行示例
> python3 fakeMstParam.zip -o mst_data --out-format json -n 100 --key 10101010232323233232323245454545

执行完毕后将会输出到 `mst_data_10101010232323233232323245454545.json` 的文件中



#### 输出数据的键含义说明：
* `PAN` 原始账号（卡号）
* `PSN` 卡片序列号
* `ATC`  计数器
* `VER`  交易版本
* `TIMESTAMP` 交易时间戳
* `EXPIRETIME` 失效日期
* `MST` 验证码

#### 程序参数说明（cli）

* `-o` 后跟 输出文件名，若不提供则默认输出到控制台
* `--out-format`  后跟输出文件的格式， 可选 `csv` 或 `json` 默认是 `csv`
* `-n` 后跟 产生记录数量，默认1
* `--key` MST主密钥明文

