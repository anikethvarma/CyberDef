# 🔄 Restart Instructions

## Issue

The error you're seeing is from an analysis that ran BEFORE the hotfix was applied. The old file (2db880d9-4724-4826-b663-ed48450ae34e) failed during analysis, so no markdown report was generated.

---

## Solution

### Step 1: Restart the Application

The hotfix has been applied, but you need to restart the application to load the fixed code.

```bash
# Stop the application (Ctrl+C in the terminal running it)
# Then restart:
python main.py
```

---

### Step 2: Upload a New File

Upload a fresh file to test the fix:

```bash
curl -X POST http://localhost:8000/api/v1/files/upload \
  -F "file=@all_threats.csv"
```

This will return a new file_id.

---

### Step 3: Analyze the New File

```bash
curl -X POST "http://localhost:8000/api/v1/analyze?file_id=<NEW_FILE_ID>"
```

This should complete successfully and generate both:
- Markdown report (.md file)
- JSON incidents file (.json file)

---

## What About the Old File?

The old file (2db880d9-4724-4826-b663-ed48450ae34e) failed before the hotfix. You have two options:

### Option 1: Re-analyze the Old File (Recommended)

```bash
curl -X POST "http://localhost:8000/api/v1/analyze?file_id=2db880d9-4724-4826-b663-ed48450ae34e"
```

This will re-run the analysis with the fixed code and generate the missing markdown report.

### Option 2: Upload Fresh

Just upload the file again and analyze the new file_id.

---

## Expected Results

After restart and re-analysis, you should see:

### In the reports/ directory:
```
20260401_HHMMSS_<file_id>_all_threats_report.md        ← NEW (markdown report)
20260401_HHMMSS_<file_id>_all_threats_incidents.json   ← Already exists
```

### In the logs:
```
✅ "Parse & normalize complete"
✅ "Tier 1 complete"
✅ "Tier 2 complete"
✅ "Tier 3 AI" (if needed)
✅ "Report saved | path=..."
✅ "Incident JSON report saved | path=..."
✅ No AttributeError
```

### In the API response:
```json
{
  "file_id": "...",
  "report_path": "reports/20260401_HHMMSS_..._report.md",
  "report_url": "/api/v1/files/<file_id>/report",
  "incident_json_path": "reports/20260401_HHMMSS_..._incidents.json",
  "incident_json_url": "/api/v1/files/<file_id>/incidents-json"
}
```

---

## Verification

### Check if report exists:
```bash
# Windows PowerShell
Get-ChildItem -Path reports -Filter "*<file_id>*"

# Should show both .md and .json files
```

### Download report via API:
```bash
curl http://localhost:8000/api/v1/files/<file_id>/report
```

---

## Troubleshooting

### If you still get "Report not found":

1. **Check the file_id is correct**
   ```bash
   curl http://localhost:8000/api/v1/files/
   ```

2. **Check if analysis completed**
   ```bash
   curl http://localhost:8000/api/v1/files/<file_id>
   ```
   Look for `status: "analyzed"`

3. **Check reports directory**
   ```bash
   Get-ChildItem -Path reports -Filter "*<file_id>*"
   ```

4. **Check logs for errors**
   ```bash
   tail -f logs/application.log
   ```

### If analysis still fails:

1. Check the error message in logs
2. Verify the hotfix is applied:
   ```bash
   # Should show commented code
   cat behavior_summary/extended_analysis.py | grep "Geographic analysis disabled"
   ```

3. Verify no syntax errors:
   ```bash
   python -m py_compile behavior_summary/extended_analysis.py
   ```

---

## Summary

1. ✅ Hotfix applied to `behavior_summary/extended_analysis.py`
2. ⏳ Restart application to load fixed code
3. ⏳ Upload new file OR re-analyze old file
4. ✅ Markdown report should be generated successfully

---

**Status**: Hotfix applied, waiting for application restart

**Next Action**: Restart the application and try again
