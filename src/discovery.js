const axios = require("axios");
const { ethers } = require("ethers");

const ALCHEMY_KEY = process.env.ALCHEMY_KEY;
const RPC = `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`;
const TVL_THRESHOLD = 1_000_000;
const MAX_AGE_DAYS = 90;

async function discoverNewTargets() {
  console.log("Discovering new DeFi targets from DeFiLlama...");

  const { data } = await axios.get("https://api.llama.fi/protocols", {
    timeout: 25000
  });

  const cutoff = Math.floor(Date.now() / 1000) - (MAX_AGE_DAYS * 86400);

  const targets = data
    .filter(p => {
      const onEthereum = p.chains?.includes("Ethereum");
      const hasTVL = p.tvl >= TVL_THRESHOLD;
      const isNew = p.listedAt && p.listedAt >= cutoff;
      const hasAddress = p.address && ethers.isAddress(p.address);
      return onEthereum && hasTVL && isNew && hasAddress;
    })
    .sort((a, b) => b.tvl - a.tvl)
    .slice(0, 20)
    .map(p => ({
      name: p.name,
      address: p.address,
      tvl: p.tvl,
      category: p.category,
      listedAt: new Date(p.listedAt * 1000).toISOString().slice(0, 10),
      slug: p.slug,
    }));

  console.log(`Found ${targets.length} new protocols (last ${MAX_AGE_DAYS} days, >$${(TVL_THRESHOLD/1e6).toFixed(0)}M TVL)`);
  return targets;
}

async function resolveProtocolContracts(slug) {
  try {
    const { data } = await axios.get(`https://api.llama.fi/protocol/${slug}`, {
      timeout: 10000
    });

    const addresses = new Set();

    if (data.address && ethers.isAddress(data.address)) {
      addresses.add(data.address.toLowerCase());
    }

    // Extract from token breakdown addresses
    if (data.currentChainTvls) {
      const chains = Object.keys(data.currentChainTvls);
      for (const chain of chains) {
        if (chain.toLowerCase().includes("ethereum")) {
          // Try to find addresses in the protocol detail
        }
      }
    }

    return [...addresses];
  } catch (e) {
    return [];
  }
}

module.exports = { discoverNewTargets, resolveProtocolContracts };
