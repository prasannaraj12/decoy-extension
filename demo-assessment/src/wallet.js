// The "bug to fix" — an ordinary-looking file so the repo seems legitimate.
function formatBalance(wei) {
  return (Number(wei) / 1e18).toFixed(4) + " ETH";
}
console.log(formatBalance("1500000000000000000"));
