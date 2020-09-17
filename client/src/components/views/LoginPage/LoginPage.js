import React, { useState } from 'react'

function LoginPage() {

    const [Email, setEmail] = useState("")
    const [Password, setPassword] = useState("")

    const onEmailHandler = (event) => {
        setEmail(event.currentTarget.value)

    }

    const onPasswordHandler = (event) => {
        setPassword(event.currentTarget.value)
    }

    const onSubmitHandler = (event) => {
        event.preventDefault(); // 이벤트 

        console.log('Email', Email)
        console.log('Password', Password)
    }

    return (
        <div style={{
            display: 'flex', justifyContent: 'center', alignItems: 'center',
            width: '100%', height: '100vh'
        }}>
            <form style={{display: 'flex', flexDirection:'column'}}
                onSubmit={onSubmitHandler}>
                <lable>Email</lable>
                <input type="email" value={Email} onChange={onEmailHandler} />
                <lable>Password</lable>
                <input type="password" value={Password} onChange={onPasswordHandler} />
                
                <br />
                <button type="submit">Login</button>
            </form>
        </div>
    )
}

export default LoginPage
