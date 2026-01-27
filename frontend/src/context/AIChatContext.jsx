import { createContext, useContext, useState, useEffect } from 'react'

const AIChatContext = createContext()

export const useAIChat = () => {
    return useContext(AIChatContext)
}

export const AIChatProvider = ({ children }) => {
    const [isOpen, setIsOpen] = useState(false)
    const [messages, setMessages] = useState([
        {
            role: 'assistant',
            content: 'Hello! I am your AI Security Assistant. How can I help you analyze your vulnerability scan results today?'
        }
    ])
    const [isLoading, setIsLoading] = useState(false)

    const toggleChat = () => setIsOpen(!isOpen)

    const sendMessage = async (content) => {
        // Add user message immediately
        const userMessage = { role: 'user', content }
        setMessages(prev => [...prev, userMessage])
        setIsLoading(true)

        try {
            // Call backend API
            const response = await fetch('http://localhost:5000/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: content, history: messages })
            })

            const data = await response.json()

            if (data.success) {
                setMessages(prev => [...prev, { role: 'assistant', content: data.reply }])
            } else {
                setMessages(prev => [...prev, { role: 'assistant', content: 'Sorry, I encountered an error creating a response.' }])
            }
        } catch (error) {
            console.error('Chat Error:', error)
            setMessages(prev => [...prev, { role: 'assistant', content: 'I am having trouble connecting to the server. Please try again later.' }])
        } finally {
            setIsLoading(false)
        }
    }

    const clearChat = () => {
        setMessages([{
            role: 'assistant',
            content: 'Chat cleared. How can I help you regarding your security scans?'
        }])
    }

    return (
        <AIChatContext.Provider value={{
            isOpen,
            toggleChat,
            messages,
            sendMessage,
            isLoading,
            clearChat
        }}>
            {children}
        </AIChatContext.Provider>
    )
}
