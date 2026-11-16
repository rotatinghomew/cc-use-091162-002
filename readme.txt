跨国人工智能风险事件协作登记网

运行验收：
python3 -m risk_exchange run --fixture fixtures/acceptance.json --database /tmp/risk_exchange.sqlite3 --output /tmp/risk_exchange-output

核验：
python3 -m risk_exchange verify --database /tmp/risk_exchange.sqlite3 --output /tmp/risk_exchange-output

全量测试：
python3 -m unittest discover -s tests -v

按模块测试：
python3 -m unittest tests.exposure_signal.test_coordination_pressure -v

构建检查：
python3 -m compileall -q risk_exchange tests
