// App.js
import React, { useState, useEffect, useMemo } from "react";
import {
  Container,
  Typography,
  Box,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Collapse,
  IconButton,
  TextField,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  CircularProgress,
  Pagination,
  Button,
  Stack,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from "@mui/material";
import {
  KeyboardArrowDown,
  KeyboardArrowUp,
  Search as SearchIcon,
  Download as DownloadIcon,
  CloudUpload as UploadIcon,
  Refresh as RefreshIcon,
  Terminal as TerminalIcon,
  Visibility as VisibilityIcon,
  PlayArrow as PlayIcon,
} from "@mui/icons-material";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip as ReTooltip, ResponsiveContainer } from "recharts";
import API_BASE_URL from "./config";  // ✅ import API base URL

const SEVERITY_COLORS = {
  CRITICAL: { chip: "error", row: "#e6ccff" },
  HIGH: { chip: "warning", row: "#fdecea" },
  MEDIUM: { chip: "info", row: "#fff8e1" },
  LOW: { chip: "success", row: "#e8f4fd" },
  INFO: { chip: "default", row: "#f7f7f7" },
};

function SeverityChip({ severity }) {
  const sev = severity.toUpperCase();
  const color = SEVERITY_COLORS[sev]?.chip || "default";
  return <Chip label={sev} color={color} size="small" />;
}

function IssueRow({ issue }) {
  const [open, setOpen] = useState(false);
  const sev = issue.severity.toUpperCase();
  const rowColor = SEVERITY_COLORS[sev]?.row || "inherit";

  return (
    <>
      <TableRow hover sx={{ backgroundColor: rowColor }}>
        <TableCell>
          <IconButton size="small" onClick={() => setOpen(!open)}>
            {open ? <KeyboardArrowUp /> : <KeyboardArrowDown />}
          </IconButton>
        </TableCell>
        <TableCell>
          <SeverityChip severity={issue.severity} />
        </TableCell>
        <TableCell>{issue.file}</TableCell>
        <TableCell>{issue.line}</TableCell>
        <TableCell>{issue.category}</TableCell>
        <TableCell>{issue.id}</TableCell>
        <TableCell>{issue.message}</TableCell>
        <TableCell>
          <code>{issue.snippet}</code>
        </TableCell>
        <TableCell>{issue.detected_by}</TableCell>
      </TableRow>
      <TableRow sx={{ backgroundColor: rowColor }}>
        <TableCell colSpan={9} style={{ paddingBottom: 0, paddingTop: 0 }}>
          <Collapse in={open} timeout="auto" unmountOnExit>
            <Box margin={1}>
              <Typography variant="subtitle2" gutterBottom>
                Suggestion:
              </Typography>
              <Typography variant="body2" paragraph>
                {issue.suggestion || "N/A"}
              </Typography>
              <Typography variant="subtitle2" gutterBottom>
                OWASP:
              </Typography>
              <Typography variant="body2" paragraph>
                {issue.owasp || "N/A"}
              </Typography>
              <Typography variant="subtitle2" gutterBottom>
                CWE:
              </Typography>
              <Typography variant="body2">{issue.cwe || "N/A"}</Typography>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

function Filters({ filters, setFilters, owaspOptions, cweOptions }) {
  return (
    <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2, alignItems: "center" }}>
      <FormControl sx={{ minWidth: 120 }}>
        <InputLabel>Severity</InputLabel>
        <Select
          value={filters.severity}
          label="Severity"
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
        >
          <MenuItem value="ALL">All</MenuItem>
          {Object.keys(SEVERITY_COLORS).map((sev) => (
            <MenuItem key={sev} value={sev}>
              {sev}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <FormControl sx={{ minWidth: 140 }}>
        <InputLabel>OWASP</InputLabel>
        <Select
          value={filters.owasp}
          label="OWASP"
          onChange={(e) => setFilters({ ...filters, owasp: e.target.value })}
        >
          <MenuItem value="ALL">All</MenuItem>
          {owaspOptions.map((tag) => (
            <MenuItem key={tag} value={tag}>
              {tag}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <FormControl sx={{ minWidth: 140 }}>
        <InputLabel>CWE</InputLabel>
        <Select
          value={filters.cwe}
          label="CWE"
          onChange={(e) => setFilters({ ...filters, cwe: e.target.value })}
        >
          <MenuItem value="ALL">All</MenuItem>
          {cweOptions.map((tag) => (
            <MenuItem key={tag} value={tag}>
              {tag}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <TextField
        label="Search"
        variant="outlined"
        size="small"
        sx={{ flexGrow: 1, minWidth: 200 }}
        value={filters.search}
        onChange={(e) => setFilters({ ...filters, search: e.target.value })}
        InputProps={{
          endAdornment: <SearchIcon />,
        }}
      />
    </Box>
  );
}

function SeverityChart({ issues }) {
  const data = useMemo(() => {
    const counts = {};
    issues.forEach((i) => {
      const sev = i.severity.toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return Object.entries(counts).map(([severity, count]) => ({
      severity,
      count,
    }));
  }, [issues]);

  return (
    <Box sx={{ width: "100%", height: 200, mb: 3 }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 20, bottom: 20 }}>
          <XAxis dataKey="severity" />
          <YAxis allowDecimals={false} />
          <ReTooltip />
          <Bar dataKey="count" fill="#1976d2" label={{ position: "top", fill: "#1976d2" }} />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

const PAGE_SIZE = 15;

function App() {
  const [issues, setIssues] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    severity: "ALL",
    owasp: "ALL",
    cwe: "ALL",
    search: "",
  });
  const [page, setPage] = useState(1);
  const [cliOpen, setCliOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  const loadReport = () => {
    setLoading(true);
    axios
      .get(`${API_BASE_URL}/reports/report.json`)   // ✅ use API_BASE_URL
      .then((res) => {
        setIssues(res.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load report.json", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    loadReport();
  }, []);

  const owaspOptions = useMemo(() => {
    const set = new Set();
    issues.forEach((i) => {
      if (i.owasp) i.owasp.split(",").forEach((tag) => tag && set.add(tag.trim()));
    });
    return Array.from(set).sort();
  }, [issues]);

  const cweOptions = useMemo(() => {
    const set = new Set();
    issues.forEach((i) => {
      if (i.cwe) i.cwe.split(",").forEach((tag) => tag && set.add(tag.trim()));
    });
    return Array.from(set).sort();
  }, [issues]);

  const filteredIssues = useMemo(() => {
    return issues.filter((issue) => {
      if (filters.severity !== "ALL" && issue.severity.toUpperCase() !== filters.severity) return false;
      if (filters.owasp !== "ALL" && !issue.owasp.includes(filters.owasp)) return false;
      if (filters.cwe !== "ALL" && !issue.cwe.includes(filters.cwe)) return false;
      if (filters.search && !JSON.stringify(issue).toLowerCase().includes(filters.search.toLowerCase())) return false;
      return true;
    });
  }, [issues, filters]);

  const pageCount = Math.ceil(filteredIssues.length / PAGE_SIZE);
  const pagedIssues = filteredIssues.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleDownload = (format) => {
    const url = `${API_BASE_URL}/reports/report.${format}`;   // ✅ use API_BASE_URL
    axios
      .get(url, { responseType: format === "html" ? "blob" : "text" })
      .then((res) => {
        const blob = new Blob([res.data], {
          type: format === "html" ? "text/html" : "application/json",
        });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `report.${format}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      })
      .catch((err) => {
        console.error(`Failed to download ${format} report`, err);
      });
  };

  const handleUpload = (event) => {
    const file = event.target.files[0];
    if (file) setSelectedFile(file);
  };

  const handleScan = () => {
    if (!selectedFile) return;

    const formData = new FormData();
    formData.append("files", selectedFile);

    axios
      .post(`${API_BASE_URL}/scan`, formData, { headers: { "Content-Type": "multipart/form-data" } })   // ✅ updated
      .then(() => {
        alert("✅ Scan completed. Report updated!");
        setSelectedFile(null);
        loadReport();
      })
      .catch((err) => {
        console.error("❌ Scan failed", err);
        alert("Scan failed. Check backend logs.");
      });
  };

  if (loading)
    return (
      <Container sx={{ textAlign: "center", mt: 10 }}>
        <CircularProgress />
        <Typography variant="h6" mt={2}>
          Loading report...
        </Typography>
      </Container>
    );

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>
        Secure Code Analyzer Report
      </Typography>

      <Stack direction="row" spacing={2} sx={{ mb: 3, flexWrap: "wrap" }}>
        <Button variant="contained" startIcon={<UploadIcon />} component="label">
          Upload File
          <input hidden type="file" onChange={handleUpload} />
        </Button>
        {selectedFile && (
          <Button variant="contained" color="success" startIcon={<PlayIcon />} onClick={handleScan}>
            Scan {selectedFile.name}
          </Button>
        )}
        <Button variant="contained" startIcon={<VisibilityIcon />} onClick={loadReport}>
          View Results
        </Button>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={() => {
            axios
              .post(`${API_BASE_URL}/refresh`)    // ✅ updated
              .then(() => {
                loadReport();
              })
              .catch((err) => {
                console.error("Refresh failed", err);
              });
          }}
        >
          Refresh
        </Button>
        <Button variant="contained" startIcon={<TerminalIcon />} onClick={() => setCliOpen(true)}>
          CLI Commands
        </Button>
        <Button variant="contained" startIcon={<DownloadIcon />} onClick={() => handleDownload("json")}>
          Download JSON
        </Button>
        <Button variant="contained" startIcon={<DownloadIcon />} onClick={() => handleDownload("html")}>
          Download HTML
        </Button>
      </Stack>

      <SeverityChart issues={filteredIssues} />
      <Filters filters={filters} setFilters={setFilters} owaspOptions={owaspOptions} cweOptions={cweOptions} />

      <Paper>
        <TableContainer>
          <Table stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell />
                <TableCell>Severity</TableCell>
                <TableCell>File</TableCell>
                <TableCell>Line</TableCell>
                <TableCell>Category</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Snippet</TableCell>
                <TableCell>Detected By</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {pagedIssues.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} align="center">
                    No issues found.
                  </TableCell>
                </TableRow>
              ) : (
                pagedIssues.map((issue, idx) => <IssueRow key={`${issue.file}-${issue.line}-${idx}`} issue={issue} />)
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {pageCount > 1 && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 3 }}>
          <Pagination count={pageCount} page={page} onChange={(_, value) => setPage(value)} color="primary" />
        </Box>
      )}

      <Box sx={{ mt: 4, textAlign: "center", color: "text.secondary" }}>
        <Typography variant="caption">
          Showing {pagedIssues.length} of {filteredIssues.length} filtered issues (Total: {issues.length})
        </Typography>
      </Box>

      {/* CLI Commands Dialog */}
      <Dialog open={cliOpen} onClose={() => setCliOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>CLI Commands</DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2" component="pre">
{`Usage: python -m secure_code_analyzer.cli [targets] [options]

Options:
  --summary        Show summary in terminal
  --out PATH       Path to save JSON report (default: reports/report.json)
  --formats        Report formats: json,html (default: all)

Examples:
  python -m secure_code_analyzer.cli samples/js/
  python -m secure_code_analyzer.cli samples/php/ --summary
  python -m secure_code_analyzer.cli samples/ --out reports/report.json --formats json,html`}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCliOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default App;
