# MCP Agent Security Research / Дослідження безпеки MCP-агентів

[EN]
## Overview
This repository contains a Proof-of-Concept (PoC) for simulating and mitigating security vulnerabilities in AI agents utilizing the Model Context Protocol (MCP). It demonstrates how Large Language Models (LLMs) interacting with local filesystems via MCP can be exploited, and evaluates different defense mechanisms.

**Key Experiments:**
* `attack_sim.py`: Simulates Indirect Prompt Injection leading to unauthorized data exfiltration (Path Traversal/Privilege Escalation).
* `defense_sim.py`: Demonstrates a basic Role-Based Access Control (RBAC) MCP Guard.
* `defense_bypass_sim.py`: Shows how basic RBAC fails against Data Poisoning (malicious code generation/execution) within allowed directories.
* `advanced_defense_sim.py`: Implements a dual-layer defense using RBAC and an "LLM-as-a-Judge" interceptor for semantic payload analysis.

## Prerequisites
* [Ollama](https://ollama.com/) with the `qwen2.5:7b` model installed (`ollama run qwen2.5:7b`).
* Python 3.10+
* Node.js (for npx to run the official `@modelcontextprotocol/server-filesystem`).

## Setup
1. Create a virtual environment: `python -m venv mcp-env`
2. Activate it: `source mcp-env/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the desired simulation script.

---

[UK]
## Опис
Цей репозиторій містить Proof-of-Concept (PoC) для симуляції та пом'якшення вразливостей у системах ШІ-агентів, що використовують Model Context Protocol (MCP). Проєкт демонструє експлуатацію LLM при взаємодії з локальною файловою системою через інструменти MCP, а також оцінює ефективність різних методів захисту.

**Основні експерименти:**
* `attack_sim.py`: Симуляція непрямої ін'єкції промптів (Indirect Prompt Injection), що призводить до витоку даних.
* `defense_sim.py`: Демонстрація базового захисту (MCP Guard) на основі контролю доступу (RBAC).
* `defense_bypass_sim.py`: Демонстрація обходу базового захисту шляхом генерації шкідливого коду (Data Poisoning) у дозволених директоріях.
* `advanced_defense_sim.py`: Дворівневий захист із використанням RBAC та перехоплювача "LLM-as-a-Judge" для семантичного аналізу намірів.

## Вимоги
* [Ollama](https://ollama.com/) зі встановленою моделлю `qwen2.5:7b` (`ollama run qwen2.5:7b`).
* Python 3.10+
* Node.js (для запуску офіційного файлового сервера через `npx`).

## Налаштування
1. Створіть віртуальне середовище: `python -m venv mcp-env`
2. Активуйте його: `source mcp-env/bin/activate`
3. Встановіть залежності: `pip install -r requirements.txt`
4. Запустіть потрібний скрипт симуляції.