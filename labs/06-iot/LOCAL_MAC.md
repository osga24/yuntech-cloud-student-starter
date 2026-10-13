# W6 在 Mac 本機操作

課程原版 `README.md` 把閘道與對帳指定在 Codespace。若改用 Mac，請在報告如實寫「Mac 本機」，不要把來源寫成 Codespace；老師是否接受此差異仍依課程驗收為準。

## 開始前

在 repo 根目錄執行。Python MQTT 套件需為 `paho-mqtt 2.1.0`；AWS 操作仍使用 `scripts/lab.py` 的 learnerlab profile。

```bash
python3 -c 'import paho.mqtt; print(paho.mqtt.__version__)'
bash scripts/verify-aws.sh
```

## 本機執行順序

1. `bash deploy/w6-start.sh`：只恢復 `.local/resources.json` 記錄的 W5 EC2/RDS。若 TCP 22/80 需要改來源，目標是 Mac 公網出口的精確 `/32`；腳本會先讀取現行規則並要求確認。若出口在多個已觀測的 `/32` 間切換，可重複指定，例如 `bash deploy/w6-start.sh --source-cidr 59.125.76.248/32 --source-cidr 59.125.76.249/32`。SSH、HTTP 只會從列出的 `/32` 允許。
2. `bash deploy/iot-up.sh`：建立本週兩個 IoT 身分與精確主題政策。憑證私鑰只存 `.local/iot/`；不要複製或貼出。
3. 本機終端 A 先執行 `python3 tools/mqtt_check.py --code g08-m2 --as consumer --sub cxe/g08-m2/gw/events --wait 60`。終端 B 再執行 `python3 tools/mqtt_check.py --code g08-m2 --as gw --pub cxe/g08-m2/gw/events`。
4. 確認 W6 程式已 commit 後執行 `./deploy/deploy.sh`。它會部署到記錄的 W5 EC2，並重啟 API 與 consumer。
5. 送一批新前綴的事件，例如 `python3 tools/gateway_sim.py --code g08-m2 --run r1`，再執行 `python3 tests/w06_reconcile.py --code g08-m2 --run r1`。每次重新對帳都要換新前綴。
6. 完成對帳後才做越權測試；依 `README.md` 步驟 6 使用記錄的 EC2 與 SSH 金鑰，並在測後啟動 consumer。
7. Mac 瀏覽器直接開 `http://<resources.json 的 public_ip>/`，輸入 operator 權杖和 `g08-m2-d01`。讀取後確認權杖欄清空，再截圖。不要把安全組開成 `0.0.0.0/0`。
8. 完成取證後執行 `bash deploy/w6-stop.sh` 停止這組 EC2/RDS；IoT 憑證維持 ACTIVE。RDS 停止最多七天可能自動啟動。

AWS 建立、啟動、網路規則變更和停止都會由腳本列明資源並要求輸入確認字串。只針對本組 `.local/resources.json` 已記錄的資源操作。
