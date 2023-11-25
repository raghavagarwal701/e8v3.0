import React, { useState } from 'react';
import classes from '../Questionnere/Questionnere.module.css';

const Question = ({ question, onOptionChange }) => {
    const [selectedOptionsValue, setSelectedOptionsValue] = useState([]);
    const [reportInputValue, setReportInputValue] = useState('');
    const [internalUseInputValue, setInternalUseInputValue] = useState('');

    const handleOptionChange = (optionValue) => {
        if (selectedOptionsValue.includes(optionValue)) {
            setSelectedOptionsValue(selectedOptionsValue.filter((value) => value !== optionValue));
        } else {
            setSelectedOptionsValue([...selectedOptionsValue, optionValue]);
        }
        // Reset both text input values when option changes
        setReportInputValue('');
        setInternalUseInputValue('');
    };

    const handleReportInputChange = (event) => {
        setReportInputValue(event.target.value);
    };

    const handleInternalUseInputChange = (event) => {
        setInternalUseInputValue(event.target.value);
    };

    const handleNextQuestion = () => {
        onOptionChange({
            selectedOptionsValue,
            reportInputValue,
            internalUseInputValue,
        });
        setSelectedOptionsValue([]);
        setReportInputValue('');
        setInternalUseInputValue('');
    };

    return (
        <div className={`${classes['question-format']}`} style={{ backgroundColor: '#211F1F' }}>
            <header className={classes.header}>
                <div className={classes['logo-container']}>
                    <img
                        src="/Cyber Ethos Logo.png"
                        alt="Cyber Ethos Logo"
                        width={319.02}
                        height={142.92}
                        className={classes.logo}
                    />
                </div>
            </header>
            <p className={classes['logo-text']}>Essential 8 Assessment</p>
            <h4 className={classes.questionhed} style={{ color: 'rgb(251, 205, 50)' }}>{question.name}</h4>
            <h6 className={classes.question} style={{ color: 'rgb(251, 205, 50)' }}>{question.question}</h6>
            <form className={classes.form}>
                {question.options.map((option, index) => (
                    <div className={classes.opt} key={index}>
                        <input
                            type="checkbox"
                            id={`option${index}`}
                            name="options"
                            value={option[1]}
                            checked={selectedOptionsValue.includes(option[1])}
                            onChange={() => handleOptionChange(option[1])}
                        />
                        <label htmlFor={`option${index}`} style={{ color: 'rgb(255, 255, 255)' }}>{option[0]}</label>
                        <br />
                    </div>
                ))}
                <div className={classes.opt}>
                    <input
                        type="text"
                        placeholder="Enter additional information for Report"
                        value={reportInputValue}
                        onChange={handleReportInputChange}
                        style={{ width: '80rem' }}
                    />
                </div>
                <div className={classes.opt}>
                    <input
                        type="text"
                        placeholder="Enter additional information for Internal Use"
                        value={internalUseInputValue}
                        onChange={handleInternalUseInputChange}
                        style={{ width: '80rem' }}
                    />
                </div>
            </form>
            <button onClick={handleNextQuestion}>
                Next
            </button>
        </div>
    );
};

export default Question;
