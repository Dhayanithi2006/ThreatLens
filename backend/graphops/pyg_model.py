"""
ThreatLens GraphOps - PyTorch Geometric (PyG) Graph Neural Network Model
Defines the GraphSAGE link prediction architecture for security knowledge graph learning,
predicting relationship plausibility and structural anomaly scores.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

from backend.graphops.pyg_converter import NODE_FEATURE_DIM, EDGE_FEATURE_DIM

logger = logging.getLogger("threatlens.graphops.pyg_model")


class StructuralGraphSageModel(nn.Module):
    """
    Graph Neural Network model combining GraphSAGE neighborhood aggregation
    with an expressive MLP edge decoder for link plausibility and structural anomaly scoring.
    """

    def __init__(
        self,
        in_channels: int = NODE_FEATURE_DIM,
        hidden_channels: int = 64,
        out_channels: int = 64,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.in_channels = in_channels
        self.hidden_channels = hidden_channels
        self.out_channels = out_channels
        self.dropout = dropout

        # GraphSAGE Convolution Layers
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, out_channels)

        # Batch Normalization / Layer Normalization for stability
        self.norm1 = nn.LayerNorm(hidden_channels)
        self.norm2 = nn.LayerNorm(out_channels)

        # Link Prediction MLP Decoder: takes concatenated [h_src, h_tgt] -> plausibility score in [0, 1]
        decoder_in = out_channels * 2
        self.decoder = nn.Sequential(
            nn.Linear(decoder_in, hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, 1),
        )

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Runs message-passing to generate L2-normalized node embeddings.
        Input x: [N, in_channels], edge_index: [2, E]
        Output: [N, out_channels]
        """
        # If graph is empty or has zero edges, handle gracefully
        if x.size(0) == 0:
            return torch.zeros((0, self.out_channels), device=x.device, dtype=x.dtype)

        if edge_index.size(1) == 0:
            # Self-isolated message-passing (no edges)
            h = F.relu(self.norm1(self.conv1(x, edge_index)))
            h = F.dropout(h, p=self.dropout, training=self.training)
            h = self.norm2(self.conv2(h, edge_index))
            return F.normalize(h, p=2, dim=-1)

        # Layer 1
        h = self.conv1(x, edge_index)
        h = self.norm1(h)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        # Layer 2
        h = self.conv2(h, edge_index)
        h = self.norm2(h)
        h = F.normalize(h, p=2, dim=-1)
        return h

    def decode(self, h: torch.Tensor, edge_pairs: torch.Tensor) -> torch.Tensor:
        """
        Predicts link plausibility logits for the specified edge pairs.
        edge_pairs: [2, num_pairs] where row 0 = source indices, row 1 = target indices
        Returns: [num_pairs] logits (apply sigmoid for probability [0, 1])
        """
        if edge_pairs.size(1) == 0 or h.size(0) == 0:
            return torch.zeros((0,), device=h.device, dtype=torch.float)

        src_indices = edge_pairs[0]
        tgt_indices = edge_pairs[1]

        # Clamp indices to valid tensor range
        src_indices = torch.clamp(src_indices, 0, h.size(0) - 1)
        tgt_indices = torch.clamp(tgt_indices, 0, h.size(0) - 1)

        h_src = h[src_indices]
        h_tgt = h[tgt_indices]

        # Concatenate embeddings
        h_pair = torch.cat([h_src, h_tgt], dim=-1)
        logits = self.decoder(h_pair).squeeze(-1)
        return logits

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_label_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Complete forward pass: encodes graph structure and decodes target edge label pairs.
        Returns: [num_target_edges] logits
        """
        h = self.encode(x, edge_index)
        return self.decode(h, edge_label_index)

    def predict_plausibility(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        src_idx: int,
        tgt_idx: int,
    ) -> float:
        """
        Evaluates a single candidate relationship (src_idx -> tgt_idx) deterministically.
        Returns predicted plausibility probability in [0.0, 1.0].
        """
        self.eval()
        with torch.no_grad():
            h = self.encode(x, edge_index)
            pairs = torch.tensor([[src_idx], [tgt_idx]], dtype=torch.long, device=x.device)
            logits = self.decode(h, pairs)
            prob = torch.sigmoid(logits).item()
            if not torch.isfinite(torch.tensor(prob)):
                prob = 0.5
            return float(max(0.0, min(1.0, prob)))

    def save_weights(self, path: str):
        """Saves model state dictionary to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        torch.save(self.state_dict(), path)
        logger.info(f"PyG model weights successfully saved to {path}")

    def load_weights(self, path: str, device: str = "cpu"):
        """Loads model state dictionary from disk."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model artifact not found at {path}")
        state_dict = torch.load(path, map_location=torch.device(device), weights_only=True)
        self.load_state_dict(state_dict)
        self.to(device)
        self.eval()
        logger.info(f"PyG model weights successfully loaded from {path}")
