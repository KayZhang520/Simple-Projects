import './style.css';
import { useReducer } from "react"
import DigitButton from './DigitButton';
import OperationButton from './OperationButton';

export const ACTIONS = {
  ADD_DIGIT: 'add-digit',
  CHOOSE_OPERATION: 'choose-operation',
  CLEAR: 'clear',
  DELETE_DIGIT: 'delete-digit',
  EVALUATE:'evaluate'
}

function reducer(state, { type, payload }){
  switch(type){
    case ACTIONS.ADD_DIGIT:
      if(state.overwrite){
        return{
          ...state,
          currentOperand:payload.digit,
          overwrite:false
        }
      }

      //avoid illegal digits
      if(payload.digit ==="0" && state.currentOperand === "0")return state
      if(payload.digit ==="." && state.currentOperand.includes("."))return state
      console.log(state)
      return {
        ...state,
        currentOperand:`${state.currentOperand || ""}${payload.digit}`
      }

    case ACTIONS.CLEAR:
      return {}
    case ACTIONS.CHOOSE_OPERATION:
      if(state.currentOperand == null && state.previousOperand == null){
        return state
      }
      if(state.previousOperand == null){
        return{
          ...state,
          operation: payload.operation,
          previousOperand: state.currentOperand,
          currentOperand: null,
        }
      }
      //operand clicked with existing 2 operands -> evaluate and update first
      return {
        ...state,
        previousOperand: evaluate(state),
        operation: payload.operation,
        currentOperand:null
      }
    case ACTIONS.EVALUATE:
      if (state.operation == null ||
        state.currentOperand == null ||
        state.previousOperand == null
      ){
        return state
      }
      else return {
        ...state,
        overwrite:true,
        previousOperand:null,
        operation:null,
        currentOperand:evaluate(state)
      }
    case ACTIONS.DELETE_DIGIT:
      if(state.overwrite){
        return {
          ...state,
          overwrite:false,
          currentOperand:null
        }
      }
      if(state.currentOperand==null) return state
      if(state.currentOperand.length===1){
        return { ...state, currentOperand:null}
      }
      return {
        ...state,
        currentOperand:state.currentOperand.slice(0, -1)
      }
  }
}

function test(){
  console.log("test function called")
  return 1
}
function evaluate({ currentOperand, previousOperand, operation}){
  const prev = parseFloat(previousOperand)
  const current = parseFloat(currentOperand)
  //return empty string if any operand is empty
  if (isNaN(prev)|| isNaN(current)) return ""
  let computation = ""
  switch (operation) {
    case "+":
      computation = prev + current
      break
    case "-":
      computation = prev - current
      break
    case "÷":
      computation = prev / current
      break
    case "*":
      computation = prev * current
      break
  }
  return computation
}

const INTEGER_FORMATTER = new Intl.NumberFormat("en-us", {
  maximumFractionDigits:0
})
function formatOperand(operand){
  if(operand == null)return
  const [integer, decimal] = operand.split('.')
  if(decimal == null) return INTEGER_FORMATTER.format(integer)
  return `${INTEGER_FORMATTER.format(integer)}.%{decimal}`
}

function App() {
  //using 'useReducer' hook to manage states, {} sets initial state to be all empty
  const [{currentOperand, previousOperand, operation},dispatch] = useReducer(
    reducer,
    {}
  )

  return (
    <div>
    <div className="calculator-grid">
      <div className="output">
        <div className="previous-operand">
          {previousOperand} {operation}
        </div>
        <div className="current-operand">
          {currentOperand}
        </div>
      </div>
      <button className="span-two" onClick={()=> dispatch({type: ACTIONS.CLEAR})}>AC</button>
      <button onClick={()=> dispatch({type: ACTIONS.DELETE_DIGIT})}>DEL</button>
      <OperationButton operation="÷" dispatch={dispatch}></OperationButton>
      <DigitButton digit="1" dispatch={dispatch}></DigitButton>
      <DigitButton digit="2" dispatch={dispatch}></DigitButton>
      <DigitButton digit="3" dispatch={dispatch}></DigitButton>
      <OperationButton operation="*" dispatch={dispatch}></OperationButton>
      <DigitButton digit="4" dispatch={dispatch}></DigitButton>
      <DigitButton digit="5" dispatch={dispatch}></DigitButton>
      <DigitButton digit="6" dispatch={dispatch}></DigitButton>
      <OperationButton operation="+" dispatch={dispatch}></OperationButton>
      <DigitButton digit="7" dispatch={dispatch}></DigitButton>
      <DigitButton digit="8" dispatch={dispatch}></DigitButton>
      <DigitButton digit="9" dispatch={dispatch}></DigitButton>
      <OperationButton operation="-" dispatch={dispatch}></OperationButton>
      <DigitButton digit="." dispatch={dispatch}></DigitButton>
      <DigitButton digit="0" dispatch={dispatch}></DigitButton>
      <button className="span-two" onClick={()=> dispatch({type: ACTIONS.EVALUATE})}>=</button>
    </div>
      <div>{currentOperand}</div>
    </div>
  );
}

export default App;
