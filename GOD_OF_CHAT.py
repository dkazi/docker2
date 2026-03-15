import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM = """
You are an expert SOC security analyst.

You analyze log attack data and answer questions.

Be technical and concise.
"""


def build_context(data):

    context = f"""
Total logs: {data['total_logs']}
Unique IPs: {data['unique_ips']}

Top Threats:
"""

    for ip in data["suspicious_ips"][:5]:

        context += f"""
IP: {ip['ip']}
Threat score: {ip['threat_score']}
Attacks: {ip['attacks']}
"""

    return context


def ask(question, data, history):

    context = build_context(data)

    messages = [{"role": "system", "content": SYSTEM}]

    messages.extend(history[-4:])

    messages.append({
        "role": "user",
        "content": f"""
Security Data:

{context}

Question:
{question}
"""
    })

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.2
    )

    answer = resp.choices[0].message.content

    history.append({"role": "user", "content": question})
    history.append({"role": "assistant", "content": answer})

    return answer
