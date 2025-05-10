from openai import OpenAI
OPENAI_API_KEY = "sk-proj-fXjUU0bazogOV-SUjBxg2VuXpdUxA1uNZPuJZUGi50ONAOrmMhKd0QR5YiK_EZpBdegQx5UgOpT3BlbkFJvQS4jXDE"\
                 "DmlBcvUvzu-okdiyMjHANsFBTecUhPGnIMOKDfficGy4wXrFQ2ms6r2GXXRY9J8PMA"


client = OpenAI(api_key=OPENAI_API_KEY)
completion = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {
            "role": "developer",
            "content": "You are a cybersecurity analyst. Be concise."
        },
        {
            "role": "user",
            "content": "Have a look at https://malpedia.caad.fkie.fraunhofer.de/library and check all the articles "
                       "that were published for the whole of last week. For each article, "
                       "tell me what are the targeted sectors and associated threat actors. Provide the full link"
                       "for the article."
        }
    ]
)

print(completion.choices[0].message.content)

