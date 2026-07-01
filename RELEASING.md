# Релиз node-accelerator (чеклист)

1. **Версия и changelog.** Поднять `NA_VERSION` в `scripts/lib/common.sh`, добавить секцию
   в `CHANGELOG.md`, обновить примеры `NA_REF=vX.Y` в `README.md` / `install.sh`.
2. **PR → CI зелёный.** Все правки кода едут веткой через PR (shellcheck + smoke-матрица).
3. **Подписать модули** (ПОСЛЕДНИМ коммитом ветки — любая правка после подписи её ломает):

   ```bash
   for f in scripts/lib/common.sh scripts/optimize.sh scripts/protect.sh \
            scripts/diagnose.sh scripts/na-report.sh scripts/rollback.sh; do
       minisign -S -s ~/.config/minisign/node-accelerator.key \
                -c "node-accelerator $(git describe --tags --abbrev=0 2>/dev/null || echo dev)" \
                -m "$f"
   done
   git add scripts/*.minisig scripts/lib/*.minisig && git commit -m "release: sign modules"
   ```

   Проверка: `minisign -V -P "$(awk 'NR==2' ~/.config/minisign/node-accelerator.pub)" -m scripts/protect.sh`.
4. **Merge** (`--no-ff`) → push main.
5. **Тег на merge-коммите + релиз:**

   ```bash
   git tag -a vX.Y <merge-sha> -m "vX.Y — <однострочник>" && git push origin vX.Y
   # релиз с выдержкой из CHANGELOG — через GitHub API/UI, vX.Y пометить latest
   ```

Заметки:
- `install.sh` сам себя подписью не проверяет (bootstrap) — его целостность обеспечивает
  пиннинг тега `NA_REF`. Подписи защищают 6 модулей, которые он докачивает.
- Приватный ключ: `~/.config/minisign/node-accelerator.key` (0600, вне репозитория).
  Публичный: `RWQrJghT9nkdBC3ntiEXF29zrS8o429WhObHKq6I7CKoftVDhQBrBscu` (в README).
- Подписи в дереве валидны только для тегов, где их коммитили: пиньте теги, не main.
