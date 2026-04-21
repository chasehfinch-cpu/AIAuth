"""
Example: Multi-Model AI Workflow with Attestation Chain

Scenario: A financial analyst uses Claude to draft a revenue forecast,
passes it to GPT-4o for critique, then uses Gemini to generate a 
summary. Each step is automatically attested, linked in a chain,
and the human reviews the final output.

This demonstrates the chain linking that makes attestation portable
across providers — the exact feature no single provider will build.
"""

import openai
import uuid
import requests

# All AI calls go through LiteLLM proxy
client = openai.OpenAI(
    api_key="your-litellm-key",
    base_url="http://localhost:4000"
)

ATTESTATION_SERVER = "http://localhost:8100"

# Create a chain ID for this workflow
chain_id = str(uuid.uuid4())
user = "analyst-jane@company.com"


# -------------------------------------------------------
# Step 1: Claude drafts the forecast
# -------------------------------------------------------
step1 = client.chat.completions.create(
    model="claude-sonnet",
    messages=[{
        "role": "user",
        "content": "Draft a Q3 revenue forecast for our SaaS division"
    }],
    user=user,
    extra_body={
        "metadata": {
            "attestation_chain_id": chain_id,
            "attestation_chain_position": 0,
            "department": "finance",
            "project": "q3-forecast",
            "attestation_tags": ["revenue", "forecast", "saas"],
            "risk_category": "financial-reporting",
        }
    }
)
forecast_draft = step1.choices[0].message.content
# Attestation record created automatically — linked to chain


# -------------------------------------------------------
# Step 2: GPT-4o critiques the forecast
# -------------------------------------------------------
step2 = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a financial analyst reviewer."},
        {"role": "user", "content": f"Critique this forecast:\n\n{forecast_draft}"}
    ],
    user=user,
    extra_body={
        "metadata": {
            "attestation_chain_id": chain_id,
            "attestation_chain_position": 1,
            "department": "finance",
            "project": "q3-forecast",
            "attestation_tags": ["review", "critique"],
        }
    }
)
critique = step2.choices[0].message.content
# Second attestation — same chain, position 1


# -------------------------------------------------------
# Step 3: Gemini generates executive summary
# -------------------------------------------------------
step3 = client.chat.completions.create(
    model="gemini-flash",
    messages=[{
        "role": "user",
        "content": f"Write a 3-paragraph executive summary:\n\n"
                   f"FORECAST:\n{forecast_draft}\n\n"
                   f"CRITIQUE:\n{critique}"
    }],
    user=user,
    extra_body={
        "metadata": {
            "attestation_chain_id": chain_id,
            "attestation_chain_position": 2,
            "department": "finance",
            "project": "q3-forecast",
            "attestation_tags": ["summary", "executive"],
        }
    }
)
summary = step3.choices[0].message.content
# Third attestation — same chain, position 2


# -------------------------------------------------------
# Step 4: View the full chain
# -------------------------------------------------------
chain = requests.get(f"{ATTESTATION_SERVER}/v1/chain/{chain_id}").json()

print(f"\n{'='*60}")
print(f"ATTESTATION CHAIN: {chain_id}")
print(f"Status: {chain['chain_status']}")
print(f"Links: {chain['length']}")
print(f"{'='*60}")

for link in chain["links"]:
    print(f"\n  [{link['position']}] {link['model']}")
    print(f"      Provider: {link['provider']}")
    print(f"      Review:   {link['review_status']}")
    print(f"      Time:     {link['created_at']}")


# -------------------------------------------------------
# Step 5: Human reviews the final output
# -------------------------------------------------------
# Jane reviews the executive summary and approves it
final_attestation_id = chain["links"][-1]["attestation_id"]

review = requests.post(
    f"{ATTESTATION_SERVER}/v1/review/{final_attestation_id}",
    json={
        "reviewer_id": user,
        "status": "approved",
        "note": "Reviewed forecast assumptions and executive summary. "
                "Adjusted growth rate from 12% to 9% before sending to CFO.",
        "review_metadata": {
            "time_spent_minutes": 15,
            "modifications_made": True,
            "forwarded_to": "cfo@company.com",
        }
    }
).json()

print(f"\n{'='*60}")
print(f"HUMAN REVIEW RECORDED")
print(f"  Reviewer:  {review['reviewer_id']}")
print(f"  Status:    {review['review_status']}")
print(f"  Timestamp: {review['reviewed_at']}")
print(f"{'='*60}")


# -------------------------------------------------------
# Step 6: Anyone can verify later
# -------------------------------------------------------
verification = requests.get(
    f"{ATTESTATION_SERVER}/v1/verify/{final_attestation_id}"
).json()

print(f"\n{'='*60}")
print("VERIFICATION RESULT")
print(json.dumps(verification, indent=2))
print(f"{'='*60}")

# The auditor can now see:
# - Three AI models contributed (Claude → GPT-4o → Gemini)
# - Jane reviewed the final output
# - She made modifications (growth rate adjustment)
# - Full chain of custody from first prompt to final approval
# - All without seeing any of the actual content
