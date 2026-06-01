# 📋 Пошаговый план запуска завтра утром

## ШАГ 1: Запустить Ollama (2-3 минуты)
```powershell
# Откройте PowerShell и выполните:
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve
```

**Ждите** пока появится строчка:
```
[GIN-debug] Loaded HTML Templates
```

Это значит Ollama готова. **НЕ закрывайте это окно!**

---

## ШАГ 2: Открыть второе PowerShell окно

Откройте **новое** PowerShell окно (НЕ закрывая первое с Ollama)

```powershell
cd D:\WEB_1
```

---

## ШАГ 3: Загрузить модель в память (если нужно)

Если модель не загружена (редко):
```powershell
ollama pull llama3.1:8b
```

Проверить что модель есть:
```powershell
ollama list
```

**Должна быть:** `llama3.1:8b`

---

## ШАГ 4: Запустить приложение

```powershell
python app.py
```

Ждите:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

## ШАГ 5: Открыть браузер

Перейди на: **http://127.0.0.1:8000**

---

## ✅ Готово!

Теперь:
- 🔵 Ollama запущена (1-е PowerShell окно)
- 🟢 Приложение работает (2-е PowerShell окно)
- 🌐 Браузер на http://127.0.0.1:8000

Сканирование будет работать с LLM рекомендациями (~5 мин на сканирование из-за Ollama).

---

## 🚨 Если что-то сломалось

### Ollama не запускается
```powershell
# Найти процесс на порту 11434 и убить его
$proc = Get-NetTCPConnection -LocalPort 11434 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
if ($proc) { Stop-Process -Id $proc -Force }

# Попробовать снова
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve
```

### Приложение не запускается
```powershell
# Убить процесс на порту 8000
$proc = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
if ($proc) { Stop-Process -Id $proc -Force }

# Попробовать снова
python app.py
```

### LLM не генерирует рекомендации
```powershell
# Проверить что Ollama работает
curl http://localhost:11434/api/tags

# Должна вернуться информация о моделях
```

---

## 📝 Хронология

1. **Ollama запущена** → Окно 1
2. **Приложение запущено** → Окно 2  
3. **Браузер** → http://127.0.0.1:8000
4. **Сканируй!**

**Не закрывай Ollama во время работы!**
