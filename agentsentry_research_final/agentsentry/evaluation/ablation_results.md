# AgentSentry Ablation Results

| Condition | TP | FP | Precision | Recall | F1 | FPR | p95 (ms) |
|---|---|---|---|---|---|---|---|
| OPA Rules Only (no anomaly engine) | 73 | 13 | 0.849 | 0.448 | 0.586 | 0.159 | 0.01 |
| SBERT Cosine Baseline Only (no OPA, no IF) | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.01 |
| Isolation Forest Only (no OPA) | 14 | 3 | 0.824 | 0.086 | 0.156 | 0.037 | 8.80 |
| AgentSentry Full Pipeline (OPA + SBERT + IF) | 87 | 16 | 0.845 | 0.534 | 0.654 | 0.195 | 9.49 |

\begin{table}[ht]
\centering
\caption{AgentSentry 4-Way Ablation Study}
\label{tab:ablation}
\begin{tabular}{lccccccc}
\toprule
Condition & TP & FP & Precision & Recall & F1 & FPR & p95 (ms) \\
\midrule
OPA Rules Only (no anomaly engine) & 73 & 13 & 0.849 & 0.448 & 0.586 & 0.159 & 0.01 \\
SBERT Cosine Baseline Only (no OPA, no IF) & 0 & 0 & 0.000 & 0.000 & 0.000 & 0.000 & 0.01 \\
Isolation Forest Only (no OPA) & 14 & 3 & 0.824 & 0.086 & 0.156 & 0.037 & 8.80 \\
AgentSentry Full Pipeline (OPA + SBERT + IF) & 87 & 16 & 0.845 & 0.534 & 0.654 & 0.195 & 9.49 \\
\bottomrule
\end{tabular}
\end{table}