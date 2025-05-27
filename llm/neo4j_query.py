from langchain_neo4j import Neo4jGraph
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
import os

from dotenv import load_dotenv

# Load environment variables
load_dotenv()
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# Neo4j connection
driver = GraphDatabase.driver("bolt://localhost:7687", auth=(NEO4J_USERNAME, NEO4J_PASSWORD))


def get_query_from_openai():

    llm = ChatOpenAI(model="gpt-4o", temperature=0, api_key=OPENAI_API_KEY)
    graph = Neo4jGraph(
        url="bolt://localhost:7687",  # Or your remote URL
        username=NEO4J_USERNAME,
        password=NEO4J_PASSWORD
    )

    schema = graph.get_schema
    question = "What is te CWE linked with CVE-2024-50801?"
    prompt = PromptTemplate.from_template("""
    You are an expert Cypher developer for Neo4j.
    You will be given a schema and a natural language question.
    ONLY return the Cypher query without explanations, markdown, or comments.
    
    Schema:
    {schema}
    
    Question:
    {question}
    """)


    chain = prompt | llm
    response = chain.invoke({"schema": schema, "question": question})
    cypher_query = response.content.strip()

    print("Generated query:\n", cypher_query)

    results = graph.query(cypher_query)
    print("Results:\n", results)


    # --- Prompt for explanation of results ---
    explain_prompt = PromptTemplate.from_template("""
    Given the original question and these Cypher results, explain the answer in plain English.

    Question:
    {question}

    Results:
    {results}

    Explanation:
    """)
    explain_chain = explain_prompt | llm
    explanation = explain_chain.invoke({"question": question, "results": str(results)})

    print("\n💡 Explanation:\n", explanation.content.strip())

if __name__ == "__main__":
    get_query_from_openai()